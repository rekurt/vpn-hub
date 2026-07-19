package application

import (
	"fmt"
	"net/netip"

	"vpn-hub/internal/domain"
)

const (
	// egressLinkBase is the /16 the point-to-point links between the main namespace
	// and each tunnel namespace are carved out of. It is deliberately separate from
	// the client subnet so a link address can never collide with a device.
	egressLinkBase = "10.90.0.0/16"
	// routeTableBase is the first policy routing table. Tables below 100 are where
	// the well-known ones live.
	routeTableBase = 100
	// egressInterface is the upstream interface inside each namespace. It can repeat
	// across tunnels precisely because they are isolated.
	egressInterface = "wg0"
	// peerVeth is the namespace end of the link. Same reasoning.
	peerVeth = "uplink0"
)

// BuildEgressSpecs derives one isolated namespace per egress tunnel.
//
// The layout is derived from the tunnel's position in the plan rather than stored,
// so it is reproducible: the same revision always yields the same namespaces,
// addresses, marks and tables, and an agent restart does not renumber a running hub.
//
// tunnels maps a tunnel ID to its already-parsed upstream configuration.
func BuildEgressSpecs(state domain.DesiredState, plan domain.FirewallPlan, tunnels map[string]domain.WireGuardTunnel) ([]domain.EgressSpec, error) {
	base, err := netip.ParsePrefix(egressLinkBase)
	if err != nil {
		return nil, fmt.Errorf("invalid egress link base: %w", err)
	}

	byID := make(map[string]domain.Tunnel, len(state.Tunnels))
	for _, tunnel := range state.Tunnels {
		byID[tunnel.ID] = tunnel
	}

	var specs []domain.EgressSpec
	index := 0
	for _, group := range plan.Egresses {
		if group.ID == domain.EgressDirect {
			continue
		}
		tunnel, known := byID[group.ID]
		if !known {
			return nil, fmt.Errorf("egress %q is selected by a profile but is not a tunnel in this revision", group.ID)
		}
		if tunnel.Type != domain.TunnelWireGuard && tunnel.Type != domain.TunnelAmneziaWG {
			// Other protocols get their own driver; refusing beats pretending.
			return nil, fmt.Errorf("tunnel %q is of type %s, which has no egress driver yet", tunnel.ID, tunnel.Type)
		}
		upstream, loaded := tunnels[tunnel.ID]
		if !loaded {
			return nil, fmt.Errorf("tunnel %q has no upstream configuration", tunnel.ID)
		}

		hostAddress, peerAddress, err := linkAddresses(base, index)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
		}

		specs = append(specs, domain.EgressSpec{
			TunnelID:    tunnel.ID,
			Namespace:   "vpn-hub-" + tunnel.ID,
			HostVeth:    EgressInterface(tunnel.ID),
			PeerVeth:    peerVeth,
			HostAddress: hostAddress,
			PeerAddress: peerAddress,
			Mark:        group.Mark,
			RouteTable:  routeTableBase + index,
			ClientCIDR:  state.Hub.ClientCIDR,
			Interface:   egressInterface,
			Tunnel:      upstream,
		})
		index++
	}
	return specs, nil
}

// linkAddresses carves the index-th /30 out of the link base, giving .1 to the main
// namespace and .2 to the tunnel's.
func linkAddresses(base netip.Prefix, index int) (host, peer string, err error) {
	const addressesPerLink = 4
	offset := index * addressesPerLink

	address := base.Addr()
	for range offset {
		address = address.Next()
		if !base.Contains(address) {
			return "", "", fmt.Errorf("ran out of link addresses in %s", base)
		}
	}
	hostAddress := address.Next()
	peerAddress := hostAddress.Next()
	if !base.Contains(peerAddress) {
		return "", "", fmt.Errorf("ran out of link addresses in %s", base)
	}
	return hostAddress.String() + "/30", peerAddress.String() + "/30", nil
}
