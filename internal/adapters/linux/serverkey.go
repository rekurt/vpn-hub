package linux

import (
	"context"
	"fmt"
	"os"

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
	return DefaultConfigDir + "/server.key"
}

func (s ServerKeyFile) file() keyFile {
	return keyFile{
		path: s.path(), noun: "hub",
		missing: func(path string) string {
			return fmt.Sprintf("no hub key at %s: run `hubctl keygen --output %s` "+
				"and put the printed public key in hub.server_public_key", path, path)
		},
		clobbered: func(path string) string {
			return fmt.Sprintf("%s already exists; replacing the hub key "+
				"would invalidate every issued client profile", path)
		},
		generate: domain.GenerateX25519KeyPair,
		validate: func(key string) error {
			_, err := domain.PublicKeyFromPrivate(key)
			return err
		},
	}
}

func (s ServerKeyFile) PrivateKey(_ context.Context) (string, error) {
	return s.file().read()
}

// Create writes a freshly generated key, refusing to overwrite an existing one:
// replacing the hub key invalidates every client profile already issued.
func (s ServerKeyFile) Create() (publicKey string, err error) {
	return s.file().create()
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
