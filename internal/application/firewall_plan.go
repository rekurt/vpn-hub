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

	proxied := make(map[string]bool, len(state.Tunnels))
	for _, tunnel := range state.Tunnels {
		// Both run their process inside the namespace, so their own connections to
		// the provider are forwarded through the main namespace rather than
		// originating there.
		proxied[tunnel.ID] = tunnel.Type == domain.TunnelXray || tunnel.Type == domain.TunnelOpenVPN
	}

	plan := domain.FirewallPlan{
		LinkBase:         egressLinkBase,
		IngressInterface: IngressInterface,
		UplinkInterface:  uplink,
		ListenPort:       listenPort,
		ManagementPort:   ManagementPort,
		ClientCIDR:       state.Hub.ClientCIDR,
		DNSAddress:       state.Hub.DNSAddress,
		Internals:        nil, // filled below, once marks are allocated
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

	// Every egress tunnel in the revision gets a group, not only those some device
	// chose as its default. An unchosen provider still has to be reachable: that is
	// what a SOCKS endpoint is for, and what makes `device set-egress` switch to a
	// tunnel that is already up rather than one that must first be built. A group
	// with no addresses in its set steers nothing by itself, so the cost is a
	// namespace that is idle until something asks for it.
	tunnelEgresses := make([]string, 0, len(grouped)+len(state.Tunnels))
	seen := make(map[string]bool, len(grouped))
	for egress := range grouped {
		if egress != domain.EgressDirect {
			tunnelEgresses = append(tunnelEgresses, egress)
			seen[egress] = true
		}
	}
	for _, tunnel := range state.Tunnels {
		if tunnel.Role == domain.RoleEgress && !seen[tunnel.ID] {
			tunnelEgresses = append(tunnelEgresses, tunnel.ID)
			seen[tunnel.ID] = true
		}
	}
	sort.Strings(tunnelEgresses)

	for index, egress := range tunnelEgresses {
		addresses := grouped[egress]
		sort.Strings(addresses)
		plan.Egresses = append(plan.Egresses, domain.EgressGroup{
			ID:        egress,
			Proxied:   proxied[egress],
			Mark:      directEgressMark + 1 + uint32(index),
			Interface: EgressInterface(egress),
			Addresses: addresses,
		})
	}

	// Internal marks continue where the egress marks stopped, so a private network
	// and an egress can never be confused for one another.
	nextMark := directEgressMark + 1 + uint32(len(tunnelEgresses))
	plan.Internals = internalNetworks(state.Tunnels, nextMark)

	return plan, nil
}

// internalNetworks gives every private-network tunnel its own set, mark and route
// table, continuing the numbering the egress groups started so the two never collide.
func internalNetworks(tunnels []domain.Tunnel, firstMark uint32) []domain.InternalNetwork {
	private := make([]domain.Tunnel, 0, len(tunnels))
	for _, tunnel := range tunnels {
		if tunnel.Role == domain.RolePrivateNetwork {
			private = append(private, tunnel)
		}
	}
	sort.Slice(private, func(i, j int) bool { return private[i].ID < private[j].ID })

	networks := make([]domain.InternalNetwork, 0, len(private))
	for index, tunnel := range private {
		routes := append([]string(nil), tunnel.Routes...)
		// The resolver for a private zone lives inside that network, so queries to it
		// must take the same path as the traffic that follows. Skip any already
		// covered by a declared subnet: an interval set rejects overlapping entries.
		routes = append(routes, uncoveredResolvers(tunnel.DNSServers, tunnel.Routes)...)
		sort.Strings(routes)

		// Normalised here rather than only during validation: the plan is what gets
		// rendered into the resolver's configuration, so it must carry the form that
		// was checked, not the form that was typed.
		zones := make([]string, 0, len(tunnel.DNSZones))
		for _, zone := range tunnel.DNSZones {
			zones = append(zones, normalizeZone(zone))
		}
		sort.Strings(zones)

		networks = append(networks, domain.InternalNetwork{
			TunnelID:  tunnel.ID,
			Mark:      firstMark + uint32(index),
			Interface: EgressInterface(tunnel.ID),
			Routes:    routes,
			Zones:     zones,
			Resolvers: append([]string(nil), tunnel.DNSServers...),
		})
	}
	return networks
}

// uncoveredResolvers turns resolver addresses into host routes, dropping those a
// declared subnet already contains.
func uncoveredResolvers(addresses, routes []string) []string {
	prefixes := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		if prefix, err := netip.ParsePrefix(route); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}

	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		covered := false
		for _, prefix := range prefixes {
			if prefix.Contains(parsed) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, fmt.Sprintf("%s/%d", parsed, parsed.BitLen()))
		}
	}
	return result
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
