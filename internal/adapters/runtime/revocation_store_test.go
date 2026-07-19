package runtime

import (
	"context"
	"testing"
)

func TestRevocationsRoundTrip(t *testing.T) {
	t.Parallel()
	store := RevocationStore{StateDir: t.TempDir()}
	ctx := context.Background()

	if err := store.Add(ctx, "laptop"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Add(ctx, "laptop"); err != nil {
		t.Fatalf("Add twice: %v", err)
	}
	if err := store.Add(ctx, "phone"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ids, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ids) != 2 || ids[0] != "laptop" || ids[1] != "phone" {
		t.Fatalf("expected [laptop phone], got %v", ids)
	}
}

// Remove is what re-issuing a profile for a revoked device relies on: without it the
// next deploy would silently drop the device again.
func TestRemoveLiftsARevocation(t *testing.T) {
	t.Parallel()
	store := RevocationStore{StateDir: t.TempDir()}
	ctx := context.Background()

	if err := store.Add(ctx, "laptop"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Remove(ctx, "laptop"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	ids, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no revocations, got %v", ids)
	}

	// Removing what is not there asks for the state already present.
	if err := store.Remove(ctx, "phone"); err != nil {
		t.Fatalf("Remove absent: %v", err)
	}
}
