package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const offsetFile = "telegram-offset"

// OffsetStore remembers the last Telegram update the bot processed, so a restart --
// which happens on every deploy -- resumes past it rather than replaying the
// backlog. Replaying a confirmed callback would re-run whatever it triggered: a
// second key rotation that kills the profiles the first one just issued, a repeated
// last-known-good swap, another profile re-issue.
//
// There is a single writer (the update loop), so no lock: the atomic write alone
// makes the value durable, and no other process reads or writes it.
type OffsetStore struct {
	StateDir string
}

func (s OffsetStore) path() string {
	return filepath.Join(s.StateDir, offsetFile)
}

// Load returns the saved offset; a missing file means "start from the beginning",
// which is correct on a first run.
func (s OffsetStore) Load() (int64, error) {
	if s.StateDir == "" {
		return 0, fmt.Errorf("state directory is required")
	}
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read telegram offset: %w", err)
	}
	offset, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode telegram offset: %w", err)
	}
	return offset, nil
}

func (s OffsetStore) Save(offset int64) error {
	if s.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	return atomicWrite(s.path(), []byte(strconv.FormatInt(offset, 10)), 0o600)
}
