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
	// egressInterface is the WireGuard interface inside each namespace. It can repeat
	// across tunnels precisely because they are isolated.
	egressInterface = "wg0"
	// proxyInterface is the tun device sing-box creates, named separately so a glance
	// at a namespace says which kind of tunnel it holds.
	proxyInterface = "sb0"
	// openvpnInterface is the tun device OpenVPN creates. Same reasoning.
	openvpnInterface = "ovpn0"
	// socksPortBase is the first SOCKS5 port. Derived from position like everything
	// else in the layout, so the same revision always yields the same ports and a
	// client's configuration does not go stale when a tunnel is added.
	socksPortBase = 11080
	// peerVeth is the namespace end of the link. Same reasoning.
	peerVeth = "uplink0"
)

// tunnelPlacement pairs a tunnel with the mark and interface the firewall plan gave
// it, whichever role it plays.
type tunnelPlacement struct {
	id     string
	mark   uint32
	device string
}

// placements lists every tunnel that needs a namespace: the egresses devices selected
// and the private networks, which are reached by destination rather than chosen.
func placements(plan domain.FirewallPlan) []tunnelPlacement {
	var result []tunnelPlacement
	for _, group := range plan.Egresses {
		if group.ID != domain.EgressDirect {
			result = append(result, tunnelPlacement{group.ID, group.Mark, group.Interface})
		}
	}
	for _, network := range plan.Internals {
		result = append(result, tunnelPlacement{network.TunnelID, network.Mark, network.Interface})
	}
	return result
}

// BuildEgressSpecs derives one isolated namespace per tunnel, for private networks as
// well as egresses. A private network is not selected by a device; it is reached
// whenever a packet is addressed to it, which is what lets one connection serve the
// internet and corporate resources at the same time.
//
// The layout is derived from the tunnel's position in the plan rather than stored,
// so it is reproducible: the same revision always yields the same namespaces,
// addresses, marks and tables, and an agent restart does not renumber a running hub.
//
// tunnels maps a tunnel ID to its already-parsed upstream configuration.
func BuildEgressSpecs(state domain.DesiredState, plan domain.FirewallPlan, tunnels map[string]domain.Upstream) ([]domain.EgressSpec, error) {
	base, err := netip.ParsePrefix(egressLinkBase)
	if err != nil {
		return nil, fmt.Errorf("invalid egress link base: %w", err)
	}

	byID := make(map[string]domain.Tunnel, len(state.Tunnels))
	for _, tunnel := range state.Tunnels {
		byID[tunnel.ID] = tunnel
	}

	var specs []domain.EgressSpec
	for index, placement := range placements(plan) {
		tunnel, known := byID[placement.id]
		if !known {
			return nil, fmt.Errorf("tunnel %q is referenced by the plan but is not in this revision", placement.id)
		}
		switch tunnel.Type {
		case domain.TunnelWireGuard, domain.TunnelAmneziaWG, domain.TunnelXray, domain.TunnelOpenVPN:
		default:
			return nil, fmt.Errorf("tunnel %q is of type %s, which has no egress driver", tunnel.ID, tunnel.Type)
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
			HostVeth:    placement.device,
			PeerVeth:    peerVeth,
			HostAddress: hostAddress,
			PeerAddress: peerAddress,
			Mark:        placement.mark,
			RouteTable:  routeTableBase + index,
			SocksPort:   uint16(socksPortBase + index),
			ClientCIDR:  state.Hub.ClientCIDR,
			Interface:   upstreamInterface(tunnel.Type),
			Type:        tunnel.Type,
			Tunnel:      upstream.WireGuard,
			Proxy:       upstream.Proxy,
			OpenVPN:     upstream.OpenVPN,
		})
	}
	return specs, nil
}

// upstreamInterface names the device that carries traffic out of a namespace.
func upstreamInterface(kind domain.TunnelType) string {
	switch kind {
	case domain.TunnelXray:
		return proxyInterface
	case domain.TunnelOpenVPN:
		return openvpnInterface
	default:
		return egressInterface
	}
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
