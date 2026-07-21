package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// RevocationStore keeps the set of device IDs that must never reach a desired state
// again. It is separate from the configuration on purpose: revoking a stolen device
// should not require editing and re-deploying the config repository.
type RevocationStore struct {
	StateDir string
}

func (s RevocationStore) path() string {
	return filepath.Join(s.StateDir, revokedStateFile)
}

func (s RevocationStore) Load(_ context.Context) ([]string, error) {
	if s.StateDir == "" {
		return nil, fmt.Errorf("state directory is required")
	}
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read revocations: %w", err)
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, fmt.Errorf("decode revocations: %w", err)
	}
	return ids, nil
}

// Add records a revocation. It is idempotent, and the list stays sorted so the file
// does not churn between writes.
func (s RevocationStore) Add(ctx context.Context, deviceID string) error {
	if s.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	// Hold the cross-process lock across the whole read-modify-write. The bot and
	// hubctl both revoke into this one file; reading before taking the lock lets two
	// concurrent revocations start from the same snapshot and the second overwrite the
	// first -- silently dropping a revocation, which for a stolen device leaves it
	// authorised.
	release, err := lockStateDir(s.StateDir)
	if err != nil {
		return err
	}
	defer release()

	existing, err := s.Load(ctx)
	if err != nil {
		return err
	}
	for _, id := range existing {
		if id == deviceID {
			return nil
		}
	}

	ids := append(existing, deviceID)
	sort.Strings(ids)
	data, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal revocations: %w", err)
	}
	return atomicWrite(s.path(), data, 0o600)
}

// Remove lifts a revocation, so a device that is re-issued a fresh key is not
// silently dropped again at the next deploy. Removing an id that is not listed is
// not an error: the state asked for is the state already there.
func (s RevocationStore) Remove(ctx context.Context, deviceID string) error {
	if s.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	// Lock before reading, for the same lost-update reason as Add.
	release, err := lockStateDir(s.StateDir)
	if err != nil {
		return err
	}
	defer release()

	existing, err := s.Load(ctx)
	if err != nil {
		return err
	}
	kept := make([]string, 0, len(existing))
	for _, id := range existing {
		if id != deviceID {
			kept = append(kept, id)
		}
	}
	if len(kept) == len(existing) {
		return nil
	}

	data, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal revocations: %w", err)
	}
	return atomicWrite(s.path(), data, 0o600)
}
