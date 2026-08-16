package application

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

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

// ValidateProfileAddress is validateProfileAddress for callers outside this
// package -- the bot, which allocates the next free address and must refuse the
// same addresses validation would. Exported so the rule is written once: an
// allocator that handed out an address the deploy then rejected would be a screen
// that offers a device and a deploy that will not take it.
func ValidateProfileAddress(value, clientCIDR string) error {
	return validateProfileAddress(value, clientCIDR)
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
	// The two addresses inside the subnet that are not usable host addresses. The
	// hub carries the whole prefix on its ingress interface, so the last one is
	// broadcast on that link and the first names the network -- a device given
	// either gets an address the kernel treats as something other than its own, and
	// the symptom is traffic that half works.
	//
	// Checked here rather than only where the bot picks the next free address,
	// because `hubctl device add --address` and a hand-edited hub.yaml reach the
	// same field without passing the allocator at all.
	if prefix.Addr().Is4() && subnet.Bits() < 31 {
		if prefix.Addr() == subnet.Addr() {
			return fmt.Errorf("profile address %q is the network address of %s", value, clientCIDR)
		}
		if !subnet.Contains(prefix.Addr().Next()) {
			return fmt.Errorf("profile address %q is the broadcast address of %s", value, clientCIDR)
		}
	}
	return nil
}

func validateHubNetwork(hub domain.Hub) error {
	clientSubnet, err := parseNetworkPrefix(hub.ClientCIDR)
	if err != nil {
		return fmt.Errorf("invalid hub client_cidr %q: %w", hub.ClientCIDR, err)
	}
	// The client subnet must not overlap the range the veth links to tunnel
	// namespaces are carved from: a device host address that lands on a link address
	// would silently break routing between the main namespace and a tunnel. The
	// separation is an invariant egress_spec relies on, so enforce it here rather than
	// discover a collision at reconcile time.
	if prefixesOverlap(hub.ClientCIDR, egressLinkBase) {
		return fmt.Errorf("hub client_cidr %q overlaps the egress link base %s; choose a client subnet outside it", hub.ClientCIDR, egressLinkBase)
	}
	if err := validateEndpoint(hub.Endpoint); err != nil {
		return err
	}
	dnsAddr, err := netip.ParseAddr(hub.DNSAddress)
	if err != nil {
		return fmt.Errorf("invalid hub dns_address %q: %w", hub.DNSAddress, err)
	}
	// The resolver address is the hub's own address on the ingress interface, so it
	// has to live inside the client subnet. Checked here rather than only at reconcile
	// time (hubAddress) so `hubctl validate` rejects it before a deploy.
	if !clientSubnet.Contains(dnsAddr) {
		return fmt.Errorf("hub dns_address %q is outside client_cidr %s", hub.DNSAddress, hub.ClientCIDR)
	}
	if err := domain.ValidatePublicKey(hub.ServerPublicKey); err != nil {
		return fmt.Errorf("hub server_public_key: %w", err)
	}
	if err := validateFallback(hub); err != nil {
		return err
	}
	return validateAWGInterface(hub.AWGInterface)
}

// validateFallback checks the alternative ingress paths. Both open a port on the
// hub, so a half-stated configuration is refused rather than silently ignored.
func validateFallback(hub domain.Hub) error {
	if hub.Fallback.UDP443 {
		port, err := hubListenPort(hub.Endpoint)
		if err != nil {
			return err
		}
		// The redirect would point the port at itself, and the packet filter would
		// carry a rule that reads as a fallback while doing nothing.
		if port == domain.RealityPort {
			return fmt.Errorf("hub.fallback.udp443 is pointless when the hub already listens on %d", domain.RealityPort)
		}
	}

	reality := hub.Fallback.Reality
	if !reality.Enabled {
		// A server_name left behind after switching the fallback off is harmless,
		// and rejecting it would make turning the feature off a two-step edit.
		return nil
	}
	if reality.ServerName == "" {
		return fmt.Errorf("hub.fallback.reality.server_name is required: " +
			"REALITY mimics a real TLS 1.3 site and hands unauthenticated connections to it")
	}
	if err := validateHostname(reality.ServerName); err != nil {
		return fmt.Errorf("hub.fallback.reality.server_name: %w", err)
	}
	// Mimicking the hub itself would send unauthenticated connections back to the
	// hub, which answers nothing on 443 but this listener -- a loop that also makes
	// the disguise pointless.
	if host, _, err := net.SplitHostPort(hub.Endpoint); err == nil &&
		canonicalHostname(host) == canonicalHostname(reality.ServerName) {
		return fmt.Errorf("hub.fallback.reality.server_name %q is the hub's own endpoint; "+
			"name a real site elsewhere for the handshake to mimic", reality.ServerName)
	}
	return nil
}

// canonicalHostname puts a DNS name in the one form two names can be compared in.
//
// validateHostname accepts a fully qualified name with its root dot, so
// "vpn.example.com." and "vpn.example.com" both pass and both mean the same host.
// Comparing them as written would let the trailing dot slip the check that stops
// the listener from mimicking the hub itself -- and handing unauthenticated
// connections back to the hub is the loop that check exists to prevent.
func canonicalHostname(value string) string {
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

// validateHostname accepts the shape of a DNS name. It deliberately does not
// resolve it: validation runs on a workstation that may not share the hub's view
// of DNS, and a name that resolves today is not the property being checked.
func validateHostname(value string) error {
	if len(value) > 253 {
		return fmt.Errorf("%q is longer than a DNS name may be", value)
	}
	if strings.ContainsAny(value, " \t\r\n/:") {
		return fmt.Errorf("%q is not a bare hostname", value)
	}
	labels := strings.Split(strings.TrimSuffix(value, "."), ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q needs at least one dot; a public site is what the handshake mimics", value)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q has an empty or over-long label", value)
		}
		// A hyphen may join a label but not open or close one. Accepting it would
		// let a name through that no resolver will answer for, and the handshake
		// target has to be a site that actually exists -- the whole disguise is
		// handing unauthenticated connections to it.
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", value)
		}
		for _, symbol := range label {
			isLetter := (symbol >= 'a' && symbol <= 'z') || (symbol >= 'A' && symbol <= 'Z')
			isDigit := symbol >= '0' && symbol <= '9'
			if !isLetter && !isDigit && symbol != '-' {
				return fmt.Errorf("%q contains %q, which a hostname may not", value, symbol)
			}
		}
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	host, rawPort, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid hub endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return fmt.Errorf("invalid hub endpoint %q: host is required", endpoint)
	}
	// The endpoint is substituted verbatim into the rendered client profile. Reject
	// control characters in the host so a value cannot inject extra profile lines --
	// net.SplitHostPort itself accepts them.
	if strings.ContainsAny(host, "\r\n") {
		return fmt.Errorf("invalid hub endpoint %q: host contains a control character", endpoint)
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
