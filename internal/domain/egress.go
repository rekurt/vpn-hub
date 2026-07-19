package domain

// WireGuardPeer is the upstream side of an egress tunnel.
type WireGuardPeer struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"-"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"keepalive,omitempty"`
}

// WireGuardTunnel is an upstream configuration, as imported from a provider's .conf.
type WireGuardTunnel struct {
	// PrivateKey is the hub's identity towards the provider and never leaves the host.
	PrivateKey string        `json:"-"`
	Addresses  []string      `json:"addresses"`
	DNS        []string      `json:"dns,omitempty"`
	MTU        int           `json:"mtu,omitempty"`
	Peer       WireGuardPeer `json:"peer"`
}

// EgressSpec is everything needed to run one upstream tunnel in isolation.
//
// Each tunnel gets its own network namespace so that a provider's routes, DNS and
// default gateway cannot reach the main namespace or each other. Traffic is steered
// in by a packet mark rather than by address, which is what lets two devices on the
// same subnet leave through different providers.
type EgressSpec struct {
	TunnelID  string `json:"tunnel_id"`
	Namespace string `json:"namespace"`

	// HostVeth lives in the main namespace, PeerVeth inside the tunnel's.
	HostVeth string `json:"host_veth"`
	PeerVeth string `json:"peer_veth"`
	// HostAddress and PeerAddress are the two ends of a /30 link network.
	HostAddress string `json:"host_address"`
	PeerAddress string `json:"peer_address"`

	// Mark selects RouteTable through an ip rule in the main namespace.
	Mark       uint32 `json:"mark"`
	RouteTable int    `json:"route_table"`

	// ClientCIDR is routed back through HostVeth from inside the namespace.
	ClientCIDR string `json:"client_cidr"`

	Interface string          `json:"interface"`
	Tunnel    WireGuardTunnel `json:"tunnel"`
}
