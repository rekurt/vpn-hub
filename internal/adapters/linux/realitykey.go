package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn-hub/internal/domain"
)

// RealityKeyFile holds the fallback listener's private key, beside the hub key and
// for the same reason: it belongs to the machine, not to a revision that gets
// compiled on a workstation and copied around.
type RealityKeyFile struct {
	Path string
}

func (s RealityKeyFile) path() string {
	if s.Path != "" {
		return s.Path
	}
	return "/etc/vpn-hub/reality.key"
}

// PrivateKey reads the key. A missing key is reported as the thing to do about it:
// the fallback is off by default, so an operator meeting this error has just turned
// it on and has no reason to know a second key exists.
func (s RealityKeyFile) PrivateKey(_ context.Context) (string, error) {
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return "", fmt.Errorf("no REALITY key at %s: run `hubctl keygen --reality` on the hub, "+
			"or turn hub.fallback.reality off", s.path())
	}
	if err != nil {
		return "", fmt.Errorf("read REALITY key: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if err := domain.ValidateRealityKey(key); err != nil {
		return "", fmt.Errorf("REALITY key at %s is unusable: %w", s.path(), err)
	}
	return key, nil
}

// Create writes a freshly generated key and refuses to overwrite one, exactly as
// the hub key does: replacing it invalidates every vless:// link already issued.
func (s RealityKeyFile) Create() (publicKey string, err error) {
	private, public, err := domain.GenerateRealityKeyPair()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}
	// O_EXCL for the same reason as the hub key: a Stat check first races a
	// concurrent writer, and a Stat error other than not-exist would read as
	// "absent" and clobber a key that is in fact there.
	handle, err := os.OpenFile(s.path(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return "", fmt.Errorf("%s already exists; replacing the REALITY key would invalidate every issued link", s.path())
		}
		return "", fmt.Errorf("write REALITY key: %w", err)
	}
	if _, err := handle.WriteString(private + "\n"); err != nil {
		_ = handle.Close()
		return "", fmt.Errorf("write REALITY key: %w", err)
	}
	if err := handle.Close(); err != nil {
		return "", fmt.Errorf("write REALITY key: %w", err)
	}
	return public, nil
}
