package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func layout(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("hub.yaml", `hub:
  endpoint: "vpn.example.test:51820"
  server_public_key: "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4="
  client_cidr: "10.80.0.0/24"
  dns_address: "10.80.0.1"
`)
	write("devices.yaml", `devices:
  - id: laptop
    address: "10.80.0.2/32"
    public_key: "6OUoSDjcaLflZn3V7U3aO6eW1Mn5HE4xPJYmzoVvnhU="
    egress: provider-nl
`)
	// Deliberately out of alphabetical order on disk.
	write("tunnels/provider-nl.yaml", `tunnels:
  - id: provider-nl
    type: wireguard
    role: egress
    source: {kind: config, value: "provider-nl.conf"}
`)
	write("tunnels/corp-a.yaml", `tunnels:
  - id: corp-a
    type: wireguard
    role: private-network
    source: {kind: config, value: "corp-a.conf"}
    routes: ["10.20.0.0/16"]
`)
	return root
}

func TestDirectoryRepositoryAssemblesTheParts(t *testing.T) {
	t.Parallel()
	cfg, err := DirectoryRepository{Path: layout(t)}.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Hub.Endpoint != "vpn.example.test:51820" {
		t.Errorf("hub was not read: %+v", cfg.Hub)
	}
	if len(cfg.Devices) != 1 || cfg.Devices[0].Egress != "provider-nl" {
		t.Errorf("devices = %+v", cfg.Devices)
	}
	if len(cfg.Tunnels) != 2 {
		t.Fatalf("expected both tunnel files, got %d", len(cfg.Tunnels))
	}
}

// A revision is a content hash, so it must not change because the filesystem
// returned entries in a different order.
func TestTunnelOrderIsStable(t *testing.T) {
	t.Parallel()
	root := layout(t)
	first, err := DirectoryRepository{Path: root}.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Tunnels[0].ID != "corp-a" || first.Tunnels[1].ID != "provider-nl" {
		t.Fatalf("tunnels are not in a stable order: %s, %s", first.Tunnels[0].ID, first.Tunnels[1].ID)
	}
}

// Devices are optional; a hub with none configured yet is a legitimate state.
func TestDevicesFileIsOptional(t *testing.T) {
	t.Parallel()
	root := layout(t)
	if err := os.Remove(filepath.Join(root, "devices.yaml")); err != nil {
		t.Fatal(err)
	}
	cfg, err := DirectoryRepository{Path: root}.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Devices) != 0 {
		t.Fatalf("expected no devices, got %+v", cfg.Devices)
	}
}

// A file under tunnels/ that holds no tunnels is a mistake worth naming, not an
// empty contribution to merge silently.
func TestEmptyTunnelFileIsRejected(t *testing.T) {
	t.Parallel()
	root := layout(t)
	if err := os.WriteFile(filepath.Join(root, "tunnels", "oops.yaml"), []byte("hub:\n  endpoint: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := DirectoryRepository{Path: root}.Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "defines no tunnels") {
		t.Fatalf("error = %v, want it to name the empty file", err)
	}
}

func TestIsDirectoryDistinguishesLayoutFromFile(t *testing.T) {
	t.Parallel()
	root := layout(t)
	if !IsDirectory(root) {
		t.Error("a directory should be read as a layout")
	}
	if IsDirectory(filepath.Join(root, "hub.yaml")) {
		t.Error("a file should not be read as a layout")
	}
}
