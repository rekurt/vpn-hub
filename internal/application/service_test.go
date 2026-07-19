package application

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

func TestBuildDesiredStateRedactsClientPrivateKeys(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	service := Service{Now: func() time.Time { return time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) }}

	state, err := service.BuildDesiredState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision == "" || len(state.Devices) != 1 {
		t.Fatalf("unexpected state: %#v", state)
	}
	if state.Devices[0].PublicKey != publicKey {
		t.Fatalf("public key = %q, want %q", state.Devices[0].PublicKey, publicKey)
	}
	serialized := mustJSON(t, state)
	if strings.Contains(serialized, privateKey) {
		t.Fatal("desired state contains a client private key")
	}
}

func TestValidateRejectsConflictingRoutes(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	cfg.Tunnels = append(cfg.Tunnels, domain.Tunnel{
		ID: "corp-b", Type: domain.TunnelOpenVPN, Role: domain.RolePrivateNetwork,
		Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "secrets/corp-b.ovpn"},
		Routes: []string{"10.20.10.0/24"},
	})

	err = Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("Validate() error = %v, want route conflict", err)
	}
}

func TestValidateRejectsConflictingDNSZones(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	cfg.Tunnels = append(cfg.Tunnels, domain.Tunnel{
		ID: "corp-b", Type: domain.TunnelOpenVPN, Role: domain.RolePrivateNetwork,
		Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "secrets/corp-b.ovpn"},
		Routes: []string{"10.50.0.0/16"}, DNSZones: []string{"dev.corp.internal"},
	})

	err = Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "DNS zone") {
		t.Fatalf("Validate() error = %v, want DNS-zone conflict", err)
	}
}

// testServerPublicKey is a real X25519 public key: validation now rejects
// placeholder strings, which is the point of it existing.
const testServerPublicKey = "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4="

func validConfig(privateKey string) domain.Config {
	return domain.Config{
		Hub: domain.Hub{
			Endpoint: "vpn.example.test:51820", ServerPublicKey: testServerPublicKey, ClientCIDR: "10.80.0.0/24", DNSAddress: "10.80.0.1",
		},
		Devices: []domain.Device{{
			ID: "macbook", Address: "10.80.0.2/32",
			PublicKey: mustPublic(privateKey), Egress: "xray",
		}},
		Tunnels: []domain.Tunnel{
			{ID: "corp", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork, Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "secrets/corp.conf"}, Routes: []string{"10.20.0.0/16"}, DNSZones: []string{"corp.internal"}},
			{ID: "xray", Type: domain.TunnelXray, Role: domain.RoleEgress, Source: domain.TunnelSource{Kind: domain.SourceXrayURI, Value: "vless://example"}, AllowedDevices: []string{"macbook"}},
		},
	}
}

// mustPublic derives the public half; the hub never stores the private one.
func mustPublic(privateKey string) string {
	public, err := domain.PublicKeyFromPrivate(privateKey)
	if err != nil {
		panic(err)
	}
	return public
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
