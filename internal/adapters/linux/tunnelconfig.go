package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
// provider credentials: the revision names the file, the host holds it. That applies
// to proxy links as much as to WireGuard configurations -- a `vless://` link carries
// a UUID, and a revision is written to disk and read back by anything that can open
// the state directory.
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

func (t TunnelConfigFiles) Load(ctx context.Context, tunnel domain.Tunnel) (domain.Upstream, error) {
	if tunnel.Source.Kind != domain.SourceConfig {
		return domain.Upstream{}, fmt.Errorf(
			"source kind %q is not readable from the host: put the value in a file under %s and use `kind: config`, "+
				"so the credential stays off the revision",
			tunnel.Source.Kind, t.dir())
	}

	content, err := t.read(ctx, tunnel.Source.Value)
	if err != nil {
		return domain.Upstream{}, err
	}

	switch tunnel.Type {
	case domain.TunnelWireGuard, domain.TunnelAmneziaWG:
		parsed, err := ParseWireGuardConfig(string(content))
		if err != nil {
			return domain.Upstream{}, fmt.Errorf("%s: %w", tunnel.Source.Value, err)
		}
		return domain.Upstream{Type: tunnel.Type, WireGuard: parsed}, nil

	case domain.TunnelXray:
		parsed, err := ParseVLESS(firstLine(string(content)))
		if err != nil {
			return domain.Upstream{}, fmt.Errorf("%s: %w", tunnel.Source.Value, err)
		}
		return domain.Upstream{Type: tunnel.Type, Proxy: parsed}, nil

	default:
		return domain.Upstream{}, fmt.Errorf("tunnel type %q has no loader", tunnel.Type)
	}
}

func (t TunnelConfigFiles) read(ctx context.Context, source string) ([]byte, error) {
	path := source
	if !filepath.IsAbs(path) {
		path = filepath.Join(t.dir(), source)
	}
	if resolved, err := filepath.Abs(path); err == nil {
		path = resolved
	}

	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no upstream configuration at %s", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if config.IsEncrypted(content) {
		if t.Secrets == nil {
			return nil, fmt.Errorf("%s is SOPS-encrypted but no decryptor is configured", path)
		}
		// Decryption goes through sops rather than a library so the age key stays
		// where sops expects it and never passes through this process's flags or
		// environment.
		return t.Secrets.Decrypt(ctx, path)
	}
	return content, nil
}

// firstLine lets a link file carry a trailing newline or a comment beneath it.
func firstLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return trimmed
		}
	}
	return ""
}
