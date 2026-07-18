//go:build unix

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockStateDir takes an exclusive advisory lock on the state directory so that a
// `hubctl deploy` and a running `vpn-hub-agent serve` cannot interleave their writes.
func lockStateDir(dir string) (release func(), err error) {
	path := filepath.Join(dir, ".lock")
	handle, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(handle.Fd()), syscall.LOCK_EX); err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(handle.Fd()), syscall.LOCK_UN)
		_ = handle.Close()
	}, nil
}
