package application

import (
	"fmt"
	"net"
	"net/netip"

	"vpn-hub/internal/domain"
)

func prefixesOverlap(a, b string) bool {
	pa, err := parseNetworkPrefix(a)
	if err != nil {
		return false
	}
	pb, err := parseNetworkPrefix(b)
	if err != nil {
		return false
	}
	return pa.Overlaps(pb)
}

func parseNetworkPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

func validateProfileAddress(value string) error {
	prefix, err := parseNetworkPrefix(value)
	if err != nil {
		return fmt.Errorf("invalid address %q", value)
	}
	bits := 32
	if prefix.Addr().Is6() {
		bits = 128
	}
	if prefix.Bits() != bits {
		return fmt.Errorf("profile address %q must be a host route", value)
	}
	return nil
}

func validateHubNetwork(hub domain.Hub) error {
	if _, err := parseNetworkPrefix(hub.ClientCIDR); err != nil {
		return fmt.Errorf("invalid hub client_cidr %q: %w", hub.ClientCIDR, err)
	}
	if _, _, err := net.SplitHostPort(hub.Endpoint); err != nil {
		return fmt.Errorf("invalid hub endpoint %q: %w", hub.Endpoint, err)
	}
	if _, err := netip.ParseAddr(hub.DNSAddress); err != nil {
		return fmt.Errorf("invalid hub dns_address %q: %w", hub.DNSAddress, err)
	}
	return nil
}
