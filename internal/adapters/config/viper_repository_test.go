package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalConfig = `hub:
  endpoint: "vpn.example.test:51820"
  server_public_key: "server-public-key"
  client_cidr: "10.80.0.0/24"
  dns_address: "10.80.0.1"
devices: []
tunnels:
  - id: corp
    type: wireguard
    role: private-network
    source:
      kind: config
      value: "secrets/corp.conf"
    dns_zones:
      - corp.internal
`

func load(t *testing.T, body string) (path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "hub.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadReadsKnownKeys(t *testing.T) {
	t.Parallel()
	cfg, err := ViperRepository{Path: load(t, minimalConfig)}.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Hub.Endpoint != "vpn.example.test:51820" {
		t.Fatalf("unexpected endpoint %q", cfg.Hub.Endpoint)
	}
	if len(cfg.Tunnels) != 1 || len(cfg.Tunnels[0].DNSZones) != 1 {
		t.Fatalf("unexpected tunnels %+v", cfg.Tunnels)
	}
}

// A misspelled key used to be discarded silently, which quietly disabled whichever
// validation depended on it.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	t.Parallel()
	typo := strings.Replace(minimalConfig, "dns_zones:", "dns_zone:", 1)
	_, err := ViperRepository{Path: load(t, typo)}.Load(context.Background())
	if err == nil {
		t.Fatal("expected the unknown key to be rejected")
	}
	if !strings.Contains(err.Error(), "dns_zone") {
		t.Fatalf("error should name the offending key, got %v", err)
	}
}

func TestLoadRequiresAPath(t *testing.T) {
	t.Parallel()
	if _, err := (ViperRepository{}).Load(context.Background()); err == nil {
		t.Fatal("expected an error for an empty path")
	}
}
