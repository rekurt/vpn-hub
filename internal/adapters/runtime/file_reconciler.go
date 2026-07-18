package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vpn-hub/internal/domain"
)

const (
	desiredStateFile = "desired-state.json"
	activeStateFile  = "active-state.json"
	revokedStateFile = "revoked-devices.json"
)

type FileReconciler struct {
	StateDir string
}

// Plan reports only what this reconciler actually performs, which is persisting the
// revision. It used to describe namespaces, veth pairs and systemd units it never
// created, so an operator reading the journal saw a running VPN where there was none.
func (r FileReconciler) Plan(_ context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	return []domain.Operation{{
		Kind:        "state",
		Resource:    activeStateFile,
		Description: fmt.Sprintf("persist revision %s; this reconciler does not touch the data plane", state.Revision),
	}}, nil
}

func (r FileReconciler) Apply(ctx context.Context, state domain.DesiredState) error {
	if r.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(r.StateDir)
	if err != nil {
		return err
	}
	defer release()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal active state: %w", err)
	}
	return atomicWrite(filepath.Join(r.StateDir, activeStateFile), data, 0o600)
}

type FileRevisionStore struct {
	StateDir string
}

func (s FileRevisionStore) Save(ctx context.Context, state domain.DesiredState) error {
	if s.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(s.StateDir)
	if err != nil {
		return err
	}
	defer release()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal desired state: %w", err)
	}
	return atomicWrite(filepath.Join(s.StateDir, desiredStateFile), data, 0o600)
}

func (s FileRevisionStore) Load(_ context.Context) (domain.DesiredState, error) {
	data, err := os.ReadFile(filepath.Join(s.StateDir, desiredStateFile))
	if err != nil {
		return domain.DesiredState{}, fmt.Errorf("read desired state: %w", err)
	}
	var state domain.DesiredState
	if err := json.Unmarshal(data, &state); err != nil {
		return domain.DesiredState{}, fmt.Errorf("decode desired state: %w", err)
	}
	return state, nil
}
