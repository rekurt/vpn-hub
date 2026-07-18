package application

import (
	"fmt"
	"net/netip"
	"sort"

	"vpn-hub/internal/domain"
)

// BuildIngressSpec derives the ingress interface configuration from a desired state.
//
// Every profile of every device becomes a peer, whatever egress it selects: the
// choice of egress is enforced by routing and the packet filter, not by refusing the
// handshake. A device that is absent from the state has no peer at all, which is how
// revocation takes effect.
func BuildIngressSpec(state domain.DesiredState, privateKey string) (domain.IngressSpec, error) {
	if privateKey == "" {
		return domain.IngressSpec{}, fmt.Errorf("the hub private key is required")
	}

	derived, err := domain.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return domain.IngressSpec{}, fmt.Errorf("hub private key: %w", err)
	}
	// A mismatch means every client profile carries the wrong peer key and no
	// handshake can ever succeed. Failing here beats a silently dead hub.
	if state.Hub.ServerPublicKey != "" && derived != state.Hub.ServerPublicKey {
		return domain.IngressSpec{}, fmt.Errorf(
			"hub private key does not match hub.server_public_key in the revision (host has %s); "+
				"update the configuration or restore the matching key", derived)
	}

	listenPort, err := hubListenPort(state.Hub.Endpoint)
	if err != nil {
		return domain.IngressSpec{}, err
	}
	address, err := hubAddress(state.Hub)
	if err != nil {
		return domain.IngressSpec{}, err
	}

	spec := domain.IngressSpec{
		Interface:  IngressInterface,
		Address:    address,
		ListenPort: listenPort,
		PrivateKey: privateKey,
		Parameters: canonicalParameters(state.Hub.AWGInterface),
	}

	for _, device := range state.Devices {
		for _, profile := range device.Profiles {
			if profile.ClientPublicKey == "" {
				return domain.IngressSpec{}, fmt.Errorf("device %q profile %q has no public key", device.ID, profile.ID)
			}
			spec.Peers = append(spec.Peers, domain.PeerSpec{
				PublicKey: profile.ClientPublicKey,
				// A peer may only claim its own address; anything wider would let one
				// device impersonate another's source address.
				AllowedIPs: []string{profile.Address},
			})
		}
	}
	sort.Slice(spec.Peers, func(i, j int) bool { return spec.Peers[i].PublicKey < spec.Peers[j].PublicKey })

	return spec, nil
}

// hubAddress is the hub's own address on the client subnet. The DNS address doubles
// as it: clients are told to resolve there, so the hub must answer on it.
func hubAddress(hub domain.Hub) (string, error) {
	address, err := netip.ParseAddr(hub.DNSAddress)
	if err != nil {
		return "", fmt.Errorf("invalid hub dns_address %q: %w", hub.DNSAddress, err)
	}
	subnet, err := parseNetworkPrefix(hub.ClientCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid hub client_cidr %q: %w", hub.ClientCIDR, err)
	}
	if !subnet.Contains(address) {
		return "", fmt.Errorf("hub dns_address %s is outside client_cidr %s", hub.DNSAddress, hub.ClientCIDR)
	}
	return fmt.Sprintf("%s/%d", address, subnet.Bits()), nil
}

func canonicalParameters(configured map[string]string) map[string]string {
	if len(configured) == 0 {
		return nil
	}
	result := make(map[string]string, len(configured))
	for name, value := range configured {
		canonical, known := domain.CanonicalAWGParameter(name)
		if !known {
			continue // validation rejects these; skipping keeps this total
		}
		result[canonical] = value
	}
	return result
}
