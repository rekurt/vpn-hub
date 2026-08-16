package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// readStateJSON decodes one of the state directory's JSON files. found is false
// for a file that is not there, which several of these stores read as a legitimate
// "nothing saved yet" rather than a failure.
func readStateJSON[T any](stateDir, name, what string) (value T, found bool, err error) {
	data, err := os.ReadFile(filepath.Join(stateDir, name))
	if os.IsNotExist(err) {
		return value, false, nil
	}
	if err != nil {
		return value, false, fmt.Errorf("read %s: %w", what, err)
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, false, fmt.Errorf("decode %s: %w", what, err)
	}
	return value, true, nil
}

// writeStateJSON replaces one of those files, atomically and under the directory
// lock, so a crash leaves the old contents and a concurrent writer waits.
//
// Deliberately not used by the stores that read-modify-write -- revocations and
// confirmations -- because those must hold the lock across the read as well, and a
// helper that takes it only for the write would turn two concurrent revocations
// into one silently lost.
func writeStateJSON(stateDir, name, what string, value any) error {
	if stateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(stateDir)
	if err != nil {
		return err
	}
	defer release()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", what, err)
	}
	return atomicWrite(filepath.Join(stateDir, name), data, 0o600)
}
