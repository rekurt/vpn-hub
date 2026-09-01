package health

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type endpointResolverStub struct {
	answers map[string][]netip.Addr
	err     error
	calls   int
}

func endpointIPv4(a, b, c, d byte) string {
	return netip.AddrFrom4([4]byte{a, b, c, d}).String()
}

func (r *endpointResolverStub) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	if network != "ip" {
		return nil, errors.New("unexpected network: " + network)
	}
	if r.err != nil {
		return nil, r.err
	}
	return r.answers[host], nil
}

func TestPinPublicEndpointRejectsSpecialUseLiterals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
	}{
		{name: "unspecified IPv4", addr: endpointIPv4(0, 0, 0, 0)},
		{name: "RFC1918 10/8", addr: endpointIPv4(10, 0, 0, 1)},
		{name: "shared address space", addr: endpointIPv4(100, 64, 0, 1)},
		{name: "loopback IPv4", addr: endpointIPv4(127, 0, 0, 1)},
		{name: "link-local IPv4", addr: endpointIPv4(169, 254, 1, 1)},
		{name: "RFC1918 172.16/12", addr: endpointIPv4(172, 16, 0, 1)},
		{name: "IETF protocol assignment", addr: endpointIPv4(192, 0, 0, 9)},
		{name: "documentation TEST-NET-1", addr: endpointIPv4(192, 0, 2, 1)},
		{name: "AS112 IPv4", addr: endpointIPv4(192, 31, 196, 1)},
		{name: "AMT IPv4", addr: endpointIPv4(192, 52, 193, 1)},
		{name: "6to4 relay", addr: endpointIPv4(192, 88, 99, 1)},
		{name: "RFC1918 192.168/16", addr: endpointIPv4(192, 168, 1, 1)},
		{name: "direct delegation AS112 IPv4", addr: endpointIPv4(192, 175, 48, 1)},
		{name: "benchmark IPv4", addr: endpointIPv4(198, 18, 0, 1)},
		{name: "documentation TEST-NET-2", addr: endpointIPv4(198, 51, 100, 1)},
		{name: "documentation TEST-NET-3", addr: endpointIPv4(203, 0, 113, 8)},
		{name: "multicast IPv4", addr: endpointIPv4(224, 0, 0, 1)},
		{name: "reserved IPv4", addr: endpointIPv4(240, 0, 0, 1)},
		{name: "unspecified IPv6", addr: "::"},
		{name: "loopback IPv6", addr: "::1"},
		{name: "NAT64 well-known", addr: "64:ff9b::808:808"},
		{name: "NAT64 local-use", addr: "64:ff9b:1::1"},
		{name: "discard-only IPv6", addr: "100::1"},
		{name: "dummy IPv6", addr: "100:0:0:1::1"},
		{name: "IETF protocol assignment IPv6", addr: "2001:1::1"},
		{name: "documentation IPv6", addr: "2001:db8::1"},
		{name: "6to4 IPv6", addr: "2002::1"},
		{name: "direct delegation AS112 IPv6", addr: "2620:4f:8000::1"},
		{name: "new documentation IPv6", addr: "3fff::1"},
		{name: "unallocated global-unicast IPv6", addr: "4000::1"},
		{name: "SRv6 SID", addr: "5f00::1"},
		{name: "unique-local IPv6", addr: "fd00::1"},
		{name: "link-local IPv6", addr: "fe80::1"},
		{name: "multicast IPv6", addr: "ff02::1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolver := &endpointResolverStub{}
			_, err := PinPublicEndpoint(context.Background(), resolver, domain.ProxyTunnel{Server: test.addr})
			if err == nil {
				t.Fatalf("PinPublicEndpoint(%s) accepted a special-use address", test.addr)
			}
			if !strings.Contains(err.Error(), "not a public endpoint") {
				t.Fatalf("PinPublicEndpoint(%s) error = %q, want public-endpoint rejection", test.addr, err)
			}
			if resolver.calls != 0 {
				t.Fatalf("IP literal caused %d DNS lookups", resolver.calls)
			}
		})
	}
}

func TestPinPublicEndpointRejectsHostnameWhenAnyAnswerIsSpecialUse(t *testing.T) {
	t.Parallel()
	resolver := &endpointResolverStub{answers: map[string][]netip.Addr{
		"provider.example": {
			netip.MustParseAddr("9.9.9.9"),
			netip.AddrFrom4([4]byte{10, 0, 0, 8}),
		},
	}}

	_, err := PinPublicEndpoint(context.Background(), resolver, domain.ProxyTunnel{Server: "provider.example"})
	if err == nil || !strings.Contains(err.Error(), "10.0.0.8 is not a public endpoint") {
		t.Fatalf("PinPublicEndpoint mixed answer error = %v", err)
	}
}

func TestPinPublicEndpointPinsSortedNormalizedAnswerAndPreservesHandshakeHosts(t *testing.T) {
	t.Parallel()
	resolver := &endpointResolverStub{answers: map[string][]netip.Addr{
		"edge.provider.example": {
			netip.MustParseAddr("9.9.9.9"),
			netip.MustParseAddr("::ffff:1.1.1.1"),
			netip.MustParseAddr("2606:4700:4700::1111"),
		},
	}}
	candidate := domain.ProxyTunnel{
		Server: "edge.provider.example",
		TLS:    domain.ProxyTLS{Enabled: true},
		Transport: domain.ProxyTransport{
			Type: "ws",
			Path: "/vpn",
		},
	}

	pinned, err := PinPublicEndpoint(context.Background(), resolver, candidate)
	if err != nil {
		t.Fatalf("PinPublicEndpoint: %v", err)
	}
	if pinned.Server != "1.1.1.1" {
		t.Errorf("Server = %q, want first normalized sorted address", pinned.Server)
	}
	if pinned.OriginServer != "edge.provider.example" {
		t.Errorf("OriginServer = %q, want original hostname", pinned.OriginServer)
	}
	if pinned.TLS.ServerName != "edge.provider.example" {
		t.Errorf("TLS server name = %q, want original hostname", pinned.TLS.ServerName)
	}
	if pinned.Transport.Host != "edge.provider.example" {
		t.Errorf("transport host = %q, want original hostname", pinned.Transport.Host)
	}
}

func TestPinPublicEndpointKeepsExplicitHandshakeHosts(t *testing.T) {
	t.Parallel()
	resolver := &endpointResolverStub{answers: map[string][]netip.Addr{
		"edge.provider.example": {netip.MustParseAddr("1.1.1.1")},
	}}
	candidate := domain.ProxyTunnel{
		Server: "edge.provider.example",
		TLS:    domain.ProxyTLS{Enabled: true, ServerName: "provider.example"},
		Transport: domain.ProxyTransport{
			Type: "httpupgrade",
			Host: "provider.example",
		},
	}

	pinned, err := PinPublicEndpoint(context.Background(), resolver, candidate)
	if err != nil {
		t.Fatalf("PinPublicEndpoint: %v", err)
	}
	if pinned.TLS.ServerName != "provider.example" {
		t.Errorf("TLS server name = %q, want explicit value", pinned.TLS.ServerName)
	}
	if pinned.Transport.Host != "provider.example" {
		t.Errorf("transport host = %q, want explicit value", pinned.Transport.Host)
	}
}

func TestPinPublicEndpointAcceptsPublicIPLiteralWithoutResolving(t *testing.T) {
	t.Parallel()
	resolver := &endpointResolverStub{err: errors.New("must not resolve")}
	candidate := domain.ProxyTunnel{Server: "2606:4700:4700::1111"}

	pinned, err := PinPublicEndpoint(context.Background(), resolver, candidate)
	if err != nil {
		t.Fatalf("PinPublicEndpoint: %v", err)
	}
	if pinned.Server != candidate.Server {
		t.Errorf("Server = %q, want %q", pinned.Server, candidate.Server)
	}
	if resolver.calls != 0 {
		t.Fatalf("IP literal caused %d DNS lookups", resolver.calls)
	}
}

func TestPinPublicEndpointFailsClosedOnResolutionErrors(t *testing.T) {
	t.Parallel()

	t.Run("resolver failure", func(t *testing.T) {
		resolver := &endpointResolverStub{err: errors.New("DNS unavailable")}
		_, err := PinPublicEndpoint(context.Background(), resolver, domain.ProxyTunnel{Server: "edge.provider.example"})
		if err == nil || !strings.Contains(err.Error(), "DNS unavailable") {
			t.Fatalf("PinPublicEndpoint resolver error = %v", err)
		}
	})

	t.Run("empty answer", func(t *testing.T) {
		resolver := &endpointResolverStub{answers: map[string][]netip.Addr{}}
		_, err := PinPublicEndpoint(context.Background(), resolver, domain.ProxyTunnel{Server: "edge.provider.example"})
		if err == nil || !strings.Contains(err.Error(), "resolved to no addresses") {
			t.Fatalf("PinPublicEndpoint empty answer error = %v", err)
		}
	})

	t.Run("missing resolver", func(t *testing.T) {
		_, err := PinPublicEndpoint(context.Background(), nil, domain.ProxyTunnel{Server: "edge.provider.example"})
		if err == nil || !strings.Contains(err.Error(), "resolver is not configured") {
			t.Fatalf("PinPublicEndpoint nil resolver error = %v", err)
		}
	})
}

func TestPinPublicEndpointsPinsEveryCandidateOrFailsClosed(t *testing.T) {
	t.Parallel()
	resolver := &endpointResolverStub{answers: map[string][]netip.Addr{
		"edge.provider.example": {netip.MustParseAddr("9.9.9.9")},
		"provider.example":      {netip.MustParseAddr("1.1.1.1")},
	}}

	pinned, err := PinPublicEndpoints(context.Background(), resolver, []domain.ProxyTunnel{
		{Server: "edge.provider.example"},
		{Server: "provider.example"},
	})
	if err != nil {
		t.Fatalf("PinPublicEndpoints: %v", err)
	}
	if pinned[0].Server != "9.9.9.9" || pinned[1].Server != "1.1.1.1" {
		t.Fatalf("pinned servers = %q, %q", pinned[0].Server, pinned[1].Server)
	}

	_, err = PinPublicEndpoints(context.Background(), resolver, []domain.ProxyTunnel{
		{Server: "edge.provider.example"},
		{Server: "10.0.0.1"},
	})
	if err == nil || !strings.Contains(err.Error(), "candidate 2") {
		t.Fatalf("unsafe list error = %v", err)
	}
}
