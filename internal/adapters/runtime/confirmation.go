package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vpn-hub/internal/domain"
)

const (
	previousStateFile = "previous-state.json"
	pendingFile       = "pending-confirmation.json"
)

// Pending records a deploy that has not been confirmed yet.
type Pending struct {
	Revision string    `json:"revision"`
	Deadline time.Time `json:"deadline"`
}

// ConfirmationStore implements deploy-and-confirm.
//
// The hub is remote and a bad revision cuts the path used to fix it -- an error in
// the ruleset severs the very SSH session you would repair it from. So a risky deploy
// keeps the previous revision and a deadline; if nobody confirms, the agent puts the
// old one back.
type ConfirmationStore struct {
	StateDir string
	Now      func() time.Time
}

func (c ConfirmationStore) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c ConfirmationStore) path(name string) string { return filepath.Join(c.StateDir, name) }

// Arm snapshots the current revision and records a deadline. Called before the new
// revision is written, so the snapshot is what to return to.
// Arm reports whether a rollback was actually armed.
//
// It cannot be on the first deploy: there is no earlier revision to return to. That
// is not a failure -- a hub not yet carrying traffic cannot lock anyone out of
// itself -- but the caller has to know, because telling an operator that an
// automatic rollback is watching a remote hub when none is, is worse than saying
// nothing.
func (c ConfirmationStore) Arm(ctx context.Context, within time.Duration, revision string) (bool, error) {
	current, err := (FileRevisionStore{StateDir: c.StateDir}).Load(ctx)
	if err != nil {
		return false, nil //nolint:nilerr // no previous revision is not a failure
	}

	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal previous state: %w", err)
	}
	if err := atomicWrite(c.path(previousStateFile), data, 0o600); err != nil {
		return false, err
	}

	pending, err := json.MarshalIndent(Pending{
		Revision: revision,
		Deadline: c.now().Add(within).UTC(),
	}, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal pending confirmation: %w", err)
	}
	return true, atomicWrite(c.path(pendingFile), pending, 0o600)
}

// Load reports the pending confirmation, if any.
func (c ConfirmationStore) Load() (Pending, bool, error) {
	data, err := os.ReadFile(c.path(pendingFile))
	if os.IsNotExist(err) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, false, fmt.Errorf("read pending confirmation: %w", err)
	}
	var pending Pending
	if err := json.Unmarshal(data, &pending); err != nil {
		return Pending{}, false, fmt.Errorf("decode pending confirmation: %w", err)
	}
	return pending, true, nil
}

// Confirm accepts the deployed revision and drops the safety net.
func (c ConfirmationStore) Confirm() error {
	if err := os.Remove(c.path(pendingFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear pending confirmation: %w", err)
	}
	return nil
}

// Expired reports whether an armed deploy has run out of time.
func (c ConfirmationStore) Expired() (bool, Pending, error) {
	pending, armed, err := c.Load()
	if err != nil || !armed {
		return false, Pending{}, err
	}
	return c.now().After(pending.Deadline), pending, nil
}

// Rollback restores the snapshotted revision and clears the pending state.
func (c ConfirmationStore) Rollback(ctx context.Context) (domain.DesiredState, error) {
	data, err := os.ReadFile(c.path(previousStateFile))
	if os.IsNotExist(err) {
		return domain.DesiredState{}, fmt.Errorf("no previous revision to return to")
	}
	if err != nil {
		return domain.DesiredState{}, fmt.Errorf("read previous state: %w", err)
	}
	var state domain.DesiredState
	if err := json.Unmarshal(data, &state); err != nil {
		return domain.DesiredState{}, fmt.Errorf("decode previous state: %w", err)
	}

	if err := (FileRevisionStore{StateDir: c.StateDir}).Save(ctx, state); err != nil {
		return domain.DesiredState{}, err
	}
	if err := c.Confirm(); err != nil {
		return domain.DesiredState{}, err
	}
	return state, nil
}
