package runtime

import (
	"context"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

func armed(t *testing.T) (ConfirmationStore, FileRevisionStore, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	clock := &now
	return ConfirmationStore{StateDir: dir, Now: func() time.Time { return *clock }},
		FileRevisionStore{StateDir: dir}, clock
}

func TestUnconfirmedDeployRollsBack(t *testing.T) {
	t.Parallel()
	store, revisions, clock := armed(t)
	ctx := context.Background()

	if err := revisions.Save(ctx, domain.DesiredState{Revision: "good"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Arm(ctx, 5*time.Minute, "risky"); err != nil {
		t.Fatal(err)
	}
	if err := revisions.Save(ctx, domain.DesiredState{Revision: "risky"}); err != nil {
		t.Fatal(err)
	}

	expired, _, err := store.Expired()
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		t.Fatal("the deadline has not passed yet")
	}

	*clock = clock.Add(6 * time.Minute)
	expired, pending, err := store.Expired()
	if err != nil {
		t.Fatal(err)
	}
	if !expired || pending.Revision != "risky" {
		t.Fatalf("expected the risky revision to expire, got %+v", pending)
	}

	restored, err := store.Rollback(ctx)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if restored.Revision != "good" {
		t.Fatalf("restored %q, want the previous revision", restored.Revision)
	}
	loaded, err := revisions.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != "good" {
		t.Fatalf("the state file still holds %q", loaded.Revision)
	}
}

func TestConfirmingDropsTheTimer(t *testing.T) {
	t.Parallel()
	store, revisions, clock := armed(t)
	ctx := context.Background()

	if err := revisions.Save(ctx, domain.DesiredState{Revision: "good"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Arm(ctx, time.Minute, "new"); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(); err != nil {
		t.Fatal(err)
	}

	*clock = clock.Add(time.Hour)
	expired, _, err := store.Expired()
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		t.Fatal("a confirmed revision must not roll back")
	}
}

// The first deploy has nothing to return to, and that is not a failure: a hub that
// was not carrying traffic cannot have locked anyone out.
func TestArmingWithoutAPreviousRevisionIsHarmless(t *testing.T) {
	t.Parallel()
	store, _, _ := armed(t)
	if _, err := store.Arm(context.Background(), time.Minute, "first"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, armedNow, err := store.Load(); err != nil || armedNow {
		t.Fatalf("expected no pending state, armed=%v err=%v", armedNow, err)
	}
}

func TestRollbackWithoutASnapshotIsAnError(t *testing.T) {
	t.Parallel()
	store, _, _ := armed(t)
	if _, err := store.Rollback(context.Background()); err == nil {
		t.Fatal("expected an error when there is nothing to return to")
	}
}

// Arming has to report whether it happened. With no earlier revision there is
// nothing to return to, and a caller that assumes otherwise tells the operator a
// remote hub is covered by a rollback that does not exist.
func TestArmingReportsWhetherThereWasAnythingToArm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	stateDir := t.TempDir()
	store := ConfirmationStore{StateDir: stateDir}

	armed, err := store.Arm(ctx, time.Minute, "first")
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if armed {
		t.Fatal("a rollback was reported for a hub with no earlier revision")
	}

	if err := (FileRevisionStore{StateDir: stateDir}).Save(ctx, domain.DesiredState{Revision: "first"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	armed, err = store.Arm(ctx, time.Minute, "second")
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !armed {
		t.Error("no rollback was armed although there was a revision to return to")
	}
}
