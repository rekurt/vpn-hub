package health

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"vpn-hub/internal/domain"
)

var globalIPv6Unicast = netip.MustParsePrefix("2000::/3")

// EndpointResolver is the DNS boundary used to validate provider-controlled
// destinations before a privileged network process receives them.
type EndpointResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var specialPurposePrefixes = []netip.Prefix{
	// IANA IPv4 Special-Purpose Address Space and multicast.
	ipv4Prefix(0, 0, 0, 0, 8),
	ipv4Prefix(10, 0, 0, 0, 8),
	ipv4Prefix(100, 64, 0, 0, 10),
	ipv4Prefix(127, 0, 0, 0, 8),
	ipv4Prefix(169, 254, 0, 0, 16),
	ipv4Prefix(172, 16, 0, 0, 12),
	ipv4Prefix(192, 0, 0, 0, 24),
	ipv4Prefix(192, 0, 2, 0, 24),
	ipv4Prefix(192, 31, 196, 0, 24),
	ipv4Prefix(192, 52, 193, 0, 24),
	ipv4Prefix(192, 88, 99, 0, 24),
	ipv4Prefix(192, 168, 0, 0, 16),
	ipv4Prefix(192, 175, 48, 0, 24),
	ipv4Prefix(198, 18, 0, 0, 15),
	ipv4Prefix(198, 51, 100, 0, 24),
	ipv4Prefix(203, 0, 113, 0, 24),
	ipv4Prefix(224, 0, 0, 0, 4),
	ipv4Prefix(240, 0, 0, 0, 4),

	// IANA IPv6 Special-Purpose Address Space and multicast.
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:1::1/128"),
	netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func ipv4Prefix(a, b, c, d byte, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits)
}

// PinPublicEndpoint resolves a provider hostname once, rejects every special-use
// result, and replaces the destination with one deterministic public address.
func PinPublicEndpoint(ctx context.Context, resolver EndpointResolver, candidate domain.ProxyTunnel) (domain.ProxyTunnel, error) {
	if literal, err := netip.ParseAddr(candidate.Server); err == nil {
		literal = literal.Unmap()
		if err := validatePublicEndpoint(literal); err != nil {
			return domain.ProxyTunnel{}, err
		}
		candidate.Server = literal.String()
		return candidate, nil
	}
	if resolver == nil {
		return domain.ProxyTunnel{}, fmt.Errorf("public endpoint resolver is not configured")
	}

	answers, err := resolver.LookupNetIP(ctx, "ip", candidate.Server)
	if err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("resolve public endpoint %q: %w", candidate.Server, err)
	}
	if len(answers) == 0 {
		return domain.ProxyTunnel{}, fmt.Errorf("public endpoint %q resolved to no addresses", candidate.Server)
	}

	addresses := make([]netip.Addr, len(answers))
	for index, answer := range answers {
		answer = answer.Unmap()
		if err := validatePublicEndpoint(answer); err != nil {
			return domain.ProxyTunnel{}, fmt.Errorf("public endpoint %q: %w", candidate.Server, err)
		}
		addresses[index] = answer
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})

	origin := candidate.Server
	candidate.Server = addresses[0].String()
	candidate.OriginServer = origin
	if candidate.TLS.ServerName == "" {
		candidate.TLS.ServerName = origin
	}
	if (candidate.Transport.Type == "ws" || candidate.Transport.Type == "httpupgrade") && candidate.Transport.Host == "" {
		candidate.Transport.Host = origin
	}
	return candidate, nil
}

// PinPublicEndpoints validates a complete provider candidate set before any of
// it reaches a canary process.
func PinPublicEndpoints(ctx context.Context, resolver EndpointResolver, candidates []domain.ProxyTunnel) ([]domain.ProxyTunnel, error) {
	pinned := make([]domain.ProxyTunnel, len(candidates))
	for index, candidate := range candidates {
		resolved, err := PinPublicEndpoint(ctx, resolver, candidate)
		if err != nil {
			return nil, fmt.Errorf("candidate %d (%s:%d): %w", index+1, candidate.Server, candidate.Port, err)
		}
		pinned[index] = resolved
	}
	return pinned, nil
}

func validatePublicEndpoint(addr netip.Addr) error {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return fmt.Errorf("%s is not a public endpoint", addr)
	}
	if addr.Is6() && !globalIPv6Unicast.Contains(addr) {
		return fmt.Errorf("%s is not a public endpoint", addr)
	}
	for _, prefix := range specialPurposePrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%s is not a public endpoint", addr)
		}
	}
	return nil
}
