package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

// A subscription names a URL, and the URL is not what the host dials. The refresher
// proves a candidate and writes the winner to a link file; this reads it. Until it
// did, the two halves of the feature could not meet: a subscription validated,
// deployed, and failed the reconcile on every tick, so the hub converged on nothing
// at all — not the ruleset, not the ingress, nothing.
func TestASubscriptionIsReadFromTheProvenLink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "subscriptions"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := "vless://24b3b0ef-1a1a-4d29-9f3f-6f0f6d0d1111@provider.example:443?security=tls&type=tcp&sni=provider.example#nl\n"
	if err := os.WriteFile(filepath.Join(dir, "subscriptions", "nl.link"), []byte(link), 0o600); err != nil {
		t.Fatal(err)
	}

	upstream, err := (TunnelConfigFiles{Dir: dir}).Load(context.Background(), domain.Tunnel{
		ID:     "nl",
		Type:   domain.TunnelXray,
		Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/sub"},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if upstream.Proxy.Server != "provider.example" {
		t.Errorf("Server = %q, want the proven candidate's", upstream.Proxy.Server)
	}
}

// Before the first refresh there is no link, and the error has to say what to do
// about it rather than reporting a missing file the operator never created.
func TestAnUnrefreshedSubscriptionSaysSo(t *testing.T) {
	t.Parallel()
	_, err := (TunnelConfigFiles{Dir: t.TempDir()}).Load(context.Background(), domain.Tunnel{
		ID:     "nl",
		Type:   domain.TunnelXray,
		Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/sub"},
	})
	if err == nil {
		t.Fatal("a subscription with no proven candidate loaded anyway")
	}
	if !strings.Contains(err.Error(), "subscription refresh nl") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
}

// A private network must not be handed a provider configuration that seizes the
// default route: inside its namespace that would capture everything instead of the
// subnets it serves.
func TestAPrivateNetworkRejectsRedirectGateway(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	config := "client\ndev tun\nproto udp\nremote provider.example 1194\nredirect-gateway def1\n"
	if err := os.WriteFile(filepath.Join(dir, "corp.ovpn"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := (TunnelConfigFiles{Dir: dir}).Load(context.Background(), domain.Tunnel{
		ID:     "corp",
		Type:   domain.TunnelOpenVPN,
		Role:   domain.RolePrivateNetwork,
		Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "corp.ovpn"},
	})
	if err == nil {
		t.Fatal("a private network was allowed to take over the default route")
	}
}
