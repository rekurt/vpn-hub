package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn-hub/internal/domain"
)

const profileKeysDir = "device-profiles"

// ErrProfileKeyNotFound means the profile predates encrypted-at-rest profile
// storage, so its private half was intentionally never kept by the hub.
var ErrProfileKeyNotFound = errors.New("device profile key not found")

// ProfileKeyStore keeps the private half of profiles issued by the bot. Files
// remain inside StateDirectory, with a directory and file mode that keep them
// readable only by the service owner.
type ProfileKeyStore struct {
	StateDir string
}

func (s ProfileKeyStore) path(deviceID string) (string, error) {
	if s.StateDir == "" {
		return "", fmt.Errorf("state directory is required")
	}
	if deviceID == "" || filepath.Base(deviceID) != deviceID || strings.ContainsRune(deviceID, '\\') {
		return "", fmt.Errorf("invalid device id")
	}
	return filepath.Join(s.StateDir, profileKeysDir, deviceID+".key"), nil
}

// Save persists one valid X25519 private key atomically, replacing the prior
// profile for the device after a reissue.
func (s ProfileKeyStore) Save(_ context.Context, deviceID, privateKey string) error {
	path, err := s.path(deviceID)
	if err != nil {
		return err
	}
	if _, err := domain.PublicKeyFromPrivate(privateKey); err != nil {
		return fmt.Errorf("validate profile private key: %w", err)
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(s.StateDir)
	if err != nil {
		return err
	}
	defer release()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect profile directory: %w", err)
	}
	return atomicWrite(path, []byte(privateKey+"\n"), 0o600)
}

// Load returns a previously issued profile key. It also validates the stored
// value, so a damaged state file can never be sent as a client profile.
func (s ProfileKeyStore) Load(_ context.Context, deviceID string) (string, error) {
	path, err := s.path(deviceID)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("%w: %s", ErrProfileKeyNotFound, deviceID)
	}
	if err != nil {
		return "", fmt.Errorf("read profile key: %w", err)
	}
	privateKey := strings.TrimSpace(string(data))
	if _, err := domain.PublicKeyFromPrivate(privateKey); err != nil {
		return "", fmt.Errorf("validate stored profile key: %w", err)
	}
	return privateKey, nil
}
