package runtime

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite is the crash-safe file replacement the state stores use, exported so
// other adapters (the YAML editor in particular) share one durability story instead
// of growing their own slightly different one.
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	return atomicWrite(path, data, mode)
}

// LockDir takes a blocking exclusive advisory lock on a directory (via <dir>/.lock),
// shared by every process that mutates files in it.
func LockDir(dir string) (release func(), err error) {
	return lockStateDir(dir)
}

// atomicWrite replaces path with data, surviving a crash at any point: the payload is
// flushed before the rename, and the parent directory is flushed after it so the new
// name is durable. The temporary file carries a random suffix, so concurrent writers
// cannot collide on it the way a fixed ".tmp" name did.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(temporary) // no-op once the rename succeeded
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", temporary, err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", temporary, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", temporary, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", temporary, path, err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
