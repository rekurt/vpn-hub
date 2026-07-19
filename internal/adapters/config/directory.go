package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"vpn-hub/internal/domain"
)

// Layout names the pieces of a configuration directory.
const (
	hubFile     = "hub.yaml"
	devicesFile = "devices.yaml"
	tunnelsDir  = "tunnels"
)

// DirectoryRepository assembles a configuration from a directory.
//
//	config/
//	  hub.yaml
//	  devices.yaml
//	  tunnels/corp-a.yaml
//
// One file per tunnel is not only tidier at four or more providers: it means a
// command that changes one tunnel rewrites one small file. Rewriting a three-hundred
// line monolith to flip a single field is how someone else's edit eventually
// disappears.
//
// A single file still works, so the example and the tests do not need a directory.
type DirectoryRepository struct {
	Path string
}

// IsDirectory reports whether the path should be read as a layout rather than a file.
func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (r DirectoryRepository) Load(ctx context.Context) (domain.Config, error) {
	if r.Path == "" {
		return domain.Config{}, fmt.Errorf("configuration path is required")
	}

	cfg, err := ViperRepository{Path: filepath.Join(r.Path, hubFile)}.Load(ctx)
	if err != nil {
		return domain.Config{}, err
	}

	// devices.yaml is optional: a hub with no devices yet is a legitimate state, and
	// so is one that keeps everything in hub.yaml.
	devicesPath := filepath.Join(r.Path, devicesFile)
	if _, err := os.Stat(devicesPath); err == nil {
		devices, err := ViperRepository{Path: devicesPath}.Load(ctx)
		if err != nil {
			return domain.Config{}, err
		}
		cfg.Devices = append(cfg.Devices, devices.Devices...)
	}

	paths, err := TunnelFiles(r.Path)
	if err != nil {
		return domain.Config{}, err
	}
	for _, path := range paths {
		tunnels, err := ViperRepository{Path: path}.Load(ctx)
		if err != nil {
			return domain.Config{}, err
		}
		if len(tunnels.Tunnels) == 0 {
			return domain.Config{}, fmt.Errorf("%s defines no tunnels; each file under %s/ holds a `tunnels:` list", path, tunnelsDir)
		}
		cfg.Tunnels = append(cfg.Tunnels, tunnels.Tunnels...)
	}
	return cfg, nil
}

// TunnelFiles lists the per-tunnel files in a configuration directory, sorted so a
// revision does not change merely because the filesystem returned a different order.
func TunnelFiles(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, tunnelsDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tunnelsDir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if extension := filepath.Ext(entry.Name()); extension != ".yaml" && extension != ".yml" {
			continue
		}
		paths = append(paths, filepath.Join(root, tunnelsDir, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}
