package linux

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type tunnelConfigResolverStub struct {
	answers map[string][]netip.Addr
	err     error
	calls   int
}

func (r *tunnelConfigResolverStub) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	if network != "ip" {
		return nil, errors.New("unexpected network: " + network)
	}
	if r.err != nil {
		return nil, r.err
	}
	return r.answers[host], nil
}

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

	resolver := &tunnelConfigResolverStub{answers: map[string][]netip.Addr{
		"provider.example": {netip.MustParseAddr("9.9.9.9")},
	}}
	upstream, err := (TunnelConfigFiles{Dir: dir, Resolver: resolver}).Load(context.Background(), domain.Tunnel{
		ID:     "nl",
		Type:   domain.TunnelXray,
		Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/sub"},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if upstream.Proxy.Server != "9.9.9.9" {
		t.Errorf("Server = %q, want the pinned candidate", upstream.Proxy.Server)
	}
	if upstream.Proxy.OriginServer != "provider.example" {
		t.Errorf("OriginServer = %q, want provider.example", upstream.Proxy.OriginServer)
	}
}

func TestVLESSFilesRejectNonPublicEndpoints(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		kind   domain.SourceKind
		source string
		path   string
	}{
		{name: "static config", kind: domain.SourceConfig, source: "edge-link", path: "edge-link"},
		{name: "subscription", kind: domain.SourceSubscription, source: "https://provider.example/sub", path: filepath.Join("subscriptions", "edge"+".link")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, test.path)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			link := "vless://24b3b0ef-1a1a-4d29-9f3f-6f0f6d0d1111@10.0.0.8:443?security=tls&type=tcp\n"
			if err := os.WriteFile(path, []byte(link), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := (TunnelConfigFiles{Dir: dir}).Load(context.Background(), domain.Tunnel{
				ID:     "edge",
				Type:   domain.TunnelXray,
				Source: domain.TunnelSource{Kind: test.kind, Value: test.source},
			})
			if err == nil || !strings.Contains(err.Error(), "not a public endpoint") {
				t.Fatalf("Load error = %v, want public-endpoint rejection", err)
			}
		})
	}
}

func TestOperatorPrivateNetworkEndpointsAreNotRestricted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	resolver := &tunnelConfigResolverStub{err: errors.New("resolver must not be used")}

	wg := strings.Replace(providerConfig, "frankfurt.example.net:51820", "10.0.0.2:51820", 1)
	if err := os.WriteFile(filepath.Join(dir, "private-wg"), []byte(wg), 0o600); err != nil {
		t.Fatal(err)
	}
	ovpn := strings.Replace(providerOVPN, "vpn.example.net 1194", "10.0.0.3 1194", 1)
	if err := os.WriteFile(filepath.Join(dir, "private-ovpn"), []byte(ovpn), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tunnel := range []domain.Tunnel{
		{ID: "private-wg", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork, Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "private-wg"}},
		{ID: "private-ovpn", Type: domain.TunnelOpenVPN, Role: domain.RoleEgress, Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "private-ovpn"}},
	} {
		if _, err := (TunnelConfigFiles{Dir: dir, Resolver: resolver}).Load(context.Background(), tunnel); err != nil {
			t.Errorf("Load %s: %v", tunnel.ID, err)
		}
	}
	if resolver.calls != 0 {
		t.Fatalf("operator endpoints caused %d DNS lookups", resolver.calls)
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
