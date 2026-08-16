package runtime

import (
	"context"
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
	return writeStateJSON(s.StateDir, desiredStateFile, "desired state", state)
}

// Load reports a missing revision as an error, unlike the stores whose absence
// means "nothing yet": there is no such thing as a hub with no desired state, so
// an absent file means the agent has never run or something removed it.
func (s FileRevisionStore) Load(_ context.Context) (domain.DesiredState, error) {
	state, found, err := readStateJSON[domain.DesiredState](s.StateDir, desiredStateFile, "desired state")
	if err != nil {
		return domain.DesiredState{}, err
	}
	if !found {
		// Wrapping os.ErrNotExist is load-bearing, not decoration: ConfirmationStore.Arm
		// tells the honest first-deploy case from a real read failure with errors.Is,
		// and a plain message there would make the first deploy look like a broken
		// state directory -- or, worse if the test had not caught it, arm a rollback
		// over a revision it could not read.
		return domain.DesiredState{}, fmt.Errorf("read desired state at %s: %w",
			filepath.Join(s.StateDir, desiredStateFile), os.ErrNotExist)
	}
	return state, nil
}
