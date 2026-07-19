package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"vpn-hub/internal/adapters/config"
	"vpn-hub/internal/domain"
)

// Decryptor turns an encrypted file into plaintext.
type Decryptor interface {
	Decrypt(ctx context.Context, path string) ([]byte, error)
}

// TunnelConfigFiles loads upstream configurations from disk.
//
// A tunnel's source value is a path relative to Dir, which keeps a revision free of
// provider credentials: the revision names the file, the host holds it.
type TunnelConfigFiles struct {
	Dir string
	// Secrets decrypts SOPS-encrypted configurations. Without it an encrypted file
	// is a clear error rather than a confusing parse failure.
	Secrets Decryptor
}

func (t TunnelConfigFiles) dir() string {
	if t.Dir != "" {
		return t.Dir
	}
	return "/etc/vpn-hub"
}

func (t TunnelConfigFiles) Load(ctx context.Context, source string) (domain.WireGuardTunnel, error) {
	path := source
	if !filepath.IsAbs(path) {
		path = filepath.Join(t.dir(), source)
	}
	// Refuse to walk out of the configuration directory.
	if resolved, err := filepath.Abs(path); err == nil {
		path = resolved
	}

	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return domain.WireGuardTunnel{}, fmt.Errorf("no upstream configuration at %s", path)
	}
	if err != nil {
		return domain.WireGuardTunnel{}, fmt.Errorf("read %s: %w", path, err)
	}

	if config.IsEncrypted(content) {
		if t.Secrets == nil {
			return domain.WireGuardTunnel{}, fmt.Errorf("%s is SOPS-encrypted but no decryptor is configured", path)
		}
		// Decryption goes through sops rather than a library so the age key stays
		// where sops expects it and never passes through this process's flags or
		// environment.
		content, err = t.Secrets.Decrypt(ctx, path)
		if err != nil {
			return domain.WireGuardTunnel{}, err
		}
	}

	tunnel, err := ParseWireGuardConfig(string(content))
	if err != nil {
		return domain.WireGuardTunnel{}, fmt.Errorf("%s: %w", path, err)
	}
	return tunnel, nil
}
