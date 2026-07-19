package application

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"

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

// validateProfileAddress requires a host route inside the hub's client subnet. An
// address outside it would be handed to a client that then cannot route back.
func validateProfileAddress(value, clientCIDR string) error {
	prefix, err := netip.ParsePrefix(value)
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

	subnet, err := parseNetworkPrefix(clientCIDR)
	if err != nil {
		return fmt.Errorf("invalid hub client_cidr %q: %w", clientCIDR, err)
	}
	if !subnet.Contains(prefix.Addr()) {
		return fmt.Errorf("profile address %q is outside hub client_cidr %s", value, clientCIDR)
	}
	return nil
}

func validateHubNetwork(hub domain.Hub) error {
	if _, err := parseNetworkPrefix(hub.ClientCIDR); err != nil {
		return fmt.Errorf("invalid hub client_cidr %q: %w", hub.ClientCIDR, err)
	}
	if err := validateEndpoint(hub.Endpoint); err != nil {
		return err
	}
	if _, err := netip.ParseAddr(hub.DNSAddress); err != nil {
		return fmt.Errorf("invalid hub dns_address %q: %w", hub.DNSAddress, err)
	}
	if err := domain.ValidatePublicKey(hub.ServerPublicKey); err != nil {
		return fmt.Errorf("hub server_public_key: %w", err)
	}
	return validateAWGInterface(hub.AWGInterface)
}

func validateEndpoint(endpoint string) error {
	host, rawPort, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid hub endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return fmt.Errorf("invalid hub endpoint %q: host is required", endpoint)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid hub endpoint %q: port must be between 1 and 65535", endpoint)
	}
	return nil
}

// validateAWGInterface guards the obfuscation parameters, which are written straight
// into client profiles: an unknown key or a value that is not a plain number would
// either break the client or inject arbitrary lines into the rendered config.
func validateAWGInterface(parameters map[string]string) error {
	names := make([]string, 0, len(parameters))
	for name := range parameters {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if _, known := domain.CanonicalAWGParameter(name); !known {
			return fmt.Errorf("hub awg_interface: unsupported parameter %q", name)
		}
		if _, err := strconv.ParseUint(parameters[name], 10, 32); err != nil {
			return fmt.Errorf("hub awg_interface: %s must be a number, got %q", name, parameters[name])
		}
	}
	return nil
}

// identifierPattern keeps IDs safe for every name derived from them: network
// interfaces, namespaces, systemd unit instances and nftables set names.
var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// maxTunnelIDLength keeps EgressInterface() within IFNAMSIZ, which allows 15
// characters, after the three-character "vh-" prefix.
const maxTunnelIDLength = 12

// maxDeviceIDLength keeps a device id short enough that every callback the bot
// builds around it -- "dev:eg:<id>:<egress>", "tun:at:<tunnel>:<id>" -- stays under
// Telegram's 64-byte callback_data limit. Beyond it those buttons would fail to
// render and the screen would silently not appear.
const maxDeviceIDLength = 32

func validateIdentifier(kind, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s %q must match %s", kind, value, identifierPattern)
	}
	return nil
}
