package application

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"vpn-hub/internal/domain"
)

const (
	// IngressInterface is the AmneziaWG interface that clients connect to.
	IngressInterface = "awg0"

	// ManagementPort has to stay reachable: the agent rewrites the ruleset on every
	// reconcile, and a ruleset without this hole locks the operator out of the host.
	ManagementPort = 22

	// directEgressMark is pinned so that adding or removing a tunnel never renumbers
	// the one egress that must keep working.
	directEgressMark = 0x100
)

// EgressInterface names the main-namespace end of the veth pair that carries traffic
// towards a tunnel's namespace.
func EgressInterface(tunnelID string) string { return "vh-" + tunnelID }

// BuildFirewallPlan derives the packet-filter policy from a desired state.
//
// It is pure apart from uplink, which names the host's default-route interface and
// can only come from observing the machine.
func BuildFirewallPlan(state domain.DesiredState, uplink string) (domain.FirewallPlan, error) {
	if uplink == "" {
		return domain.FirewallPlan{}, fmt.Errorf("uplink interface is required")
	}

	listenPort, err := hubListenPort(state.Hub.Endpoint)
	if err != nil {
		return domain.FirewallPlan{}, err
	}

	grouped := make(map[string][]string)
	for _, device := range state.Devices {
		address, err := hostAddress(device.Address)
		if err != nil {
			return domain.FirewallPlan{}, fmt.Errorf("device %q: %w", device.ID, err)
		}
		grouped[device.Egress] = append(grouped[device.Egress], address)
	}

	plan := domain.FirewallPlan{
		IngressInterface: IngressInterface,
		UplinkInterface:  uplink,
		ListenPort:       listenPort,
		ManagementPort:   ManagementPort,
		ClientCIDR:       state.Hub.ClientCIDR,
		DNSAddress:       state.Hub.DNSAddress,
		InternalRoutes:   internalRoutes(state.Tunnels),
		Egresses:         make([]domain.EgressGroup, 0, len(grouped)),
	}

	if addresses := grouped[domain.EgressDirect]; len(addresses) > 0 {
		sort.Strings(addresses)
		plan.Egresses = append(plan.Egresses, domain.EgressGroup{
			ID:        domain.EgressDirect,
			Mark:      directEgressMark,
			Interface: uplink,
			Addresses: addresses,
		})
	}

	tunnelEgresses := make([]string, 0, len(grouped))
	for egress := range grouped {
		if egress != domain.EgressDirect {
			tunnelEgresses = append(tunnelEgresses, egress)
		}
	}
	sort.Strings(tunnelEgresses)

	for index, egress := range tunnelEgresses {
		addresses := grouped[egress]
		sort.Strings(addresses)
		plan.Egresses = append(plan.Egresses, domain.EgressGroup{
			ID:        egress,
			Mark:      directEgressMark + 1 + uint32(index),
			Interface: EgressInterface(egress),
			Addresses: addresses,
		})
	}

	return plan, nil
}

// internalRoutes collects the destinations served by private-network tunnels. They
// outrank a profile's default egress, so they are matched before it.
func internalRoutes(tunnels []domain.Tunnel) []string {
	var routes []string
	for _, tunnel := range tunnels {
		if tunnel.Role != domain.RolePrivateNetwork {
			continue
		}
		routes = append(routes, tunnel.Routes...)
	}
	sort.Strings(routes)
	return routes
}

func hubListenPort(endpoint string) (uint16, error) {
	_, rawPort, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, fmt.Errorf("invalid hub endpoint %q: %w", endpoint, err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("invalid hub endpoint %q: port must be between 1 and 65535", endpoint)
	}
	return uint16(port), nil
}

// hostAddress strips the prefix length from a profile address, which nftables sets
// of type ipv4_addr do not accept.
func hostAddress(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", fmt.Errorf("invalid address %q", value)
	}
	return prefix.Addr().String(), nil
}
