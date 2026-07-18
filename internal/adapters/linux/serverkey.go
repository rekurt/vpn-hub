package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn-hub/internal/domain"
)

// ServerKeyFile holds the hub's own private key on disk.
//
// The key deliberately never travels in a revision: a revision is compiled on a
// workstation and copied around, while this stays on the machine that needs it.
type ServerKeyFile struct {
	Path string
}

func (s ServerKeyFile) path() string {
	if s.Path != "" {
		return s.Path
	}
	return "/etc/vpn-hub/server.key"
}

func (s ServerKeyFile) PrivateKey(_ context.Context) (string, error) {
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return "", fmt.Errorf("no hub key at %s: run `hubctl keygen --output %s` and put the printed public key in hub.server_public_key", s.path(), s.path())
	}
	if err != nil {
		return "", fmt.Errorf("read hub key: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if _, err := domain.PublicKeyFromPrivate(key); err != nil {
		return "", fmt.Errorf("hub key at %s is unusable: %w", s.path(), err)
	}
	return key, nil
}

// Create writes a freshly generated key, refusing to overwrite an existing one:
// replacing the hub key invalidates every client profile already issued.
func (s ServerKeyFile) Create() (publicKey string, err error) {
	if _, err := os.Stat(s.path()); err == nil {
		return "", fmt.Errorf("%s already exists; replacing the hub key would invalidate every issued client profile", s.path())
	}
	private, public, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(s.path(), []byte(private+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write hub key: %w", err)
	}
	return public, nil
}
