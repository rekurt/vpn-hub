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
	revokedStateFile = "revoked-devices.json"
)

// FileRevisionStore holds the revision the agent converges on. It is the only channel
// between the workstation that compiles a revision and the host that applies it.
type FileRevisionStore struct {
	StateDir string
}

func (s FileRevisionStore) Save(_ context.Context, state domain.DesiredState) error {
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
