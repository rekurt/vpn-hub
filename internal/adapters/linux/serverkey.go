package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
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
	private, public, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}
	// O_EXCL makes "refuse to overwrite" atomic and correct. A Stat check first races
	// a concurrent writer, and a Stat error other than not-exist (e.g. EACCES) would
	// be read as "absent" and clobber a key that is in fact present -- which would
	// invalidate every issued client profile.
	handle, err := os.OpenFile(s.path(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return "", fmt.Errorf("%s already exists; replacing the hub key would invalidate every issued client profile", s.path())
		}
		return "", fmt.Errorf("write hub key: %w", err)
	}
	if _, err := handle.WriteString(private + "\n"); err != nil {
		_ = handle.Close()
		return "", fmt.Errorf("write hub key: %w", err)
	}
	if err := handle.Close(); err != nil {
		return "", fmt.Errorf("write hub key: %w", err)
	}
	return public, nil
}

// Rotate replaces the key, keeping the old one beside it. Create's refusal stands
// for accidents; rotation is the deliberate act, and it is only survivable as part
// of a flow that re-issues every profile -- which is why the previous key is kept:
// until the new revision deploys, it is what the devices still speak.
func (s ServerKeyFile) Rotate() (publicKey string, err error) {
	current, err := os.ReadFile(s.path())
	if err != nil {
		return "", fmt.Errorf("read current hub key: %w (nothing was changed)", err)
	}
	previous := s.path() + ".previous"
	if err := os.WriteFile(previous, current, 0o600); err != nil {
		return "", fmt.Errorf("keep the previous key: %w (nothing was changed)", err)
	}

	private, public, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return "", err
	}
	if err := runtimeadapter.AtomicWrite(s.path(), []byte(private+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write the new hub key: %w (the previous key is intact at %s)", err, previous)
	}
	return public, nil
}
