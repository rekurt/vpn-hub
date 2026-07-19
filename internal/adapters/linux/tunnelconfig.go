package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"vpn-hub/internal/domain"
)

// TunnelConfigFiles loads upstream configurations from disk.
//
// A tunnel's source value is a path relative to Dir, which keeps a revision free of
// provider credentials: the revision names the file, the host holds it.
type TunnelConfigFiles struct {
	Dir string
}

func (t TunnelConfigFiles) dir() string {
	if t.Dir != "" {
		return t.Dir
	}
	return "/etc/vpn-hub"
}

func (t TunnelConfigFiles) Load(_ context.Context, source string) (domain.WireGuardTunnel, error) {
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

	tunnel, err := ParseWireGuardConfig(string(content))
	if err != nil {
		return domain.WireGuardTunnel{}, fmt.Errorf("%s: %w", path, err)
	}
	return tunnel, nil
}
