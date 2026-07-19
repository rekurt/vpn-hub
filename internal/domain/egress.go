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

	Interface string `json:"interface"`

	// Type selects which upstream below is meaningful.
	Type    TunnelType      `json:"type"`
	Tunnel  WireGuardTunnel `json:"tunnel,omitempty"`
	Proxy   ProxyTunnel     `json:"proxy,omitempty"`
	OpenVPN OpenVPNTunnel   `json:"openvpn,omitempty"`
}

// Upstream is a tunnel's provider-side configuration, whichever form it takes.
type Upstream struct {
	Type      TunnelType
	WireGuard WireGuardTunnel
	Proxy     ProxyTunnel
	OpenVPN   OpenVPNTunnel
}

// OpenVPNRemote is one server a configuration offers.
type OpenVPNRemote struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}

// OpenVPNTunnel is a provider's .ovpn, interpreted only as far as the hub must act
// on it. The original text is carried through and handed to OpenVPN, which
// understands its own options better than a reimplementation would.
type OpenVPNTunnel struct {
	Remotes  []OpenVPNRemote `json:"remotes"`
	Protocol string          `json:"protocol,omitempty"`
	Device   string          `json:"device,omitempty"`
	// RedirectsGateway means the provider expects to become the default route. Inside
	// a namespace that is exactly right for an egress and exactly wrong for a private
	// network, which would silently capture everything.
	RedirectsGateway bool `json:"redirects_gateway"`
	// NeedsCredentials marks a configuration that would stop and prompt.
	NeedsCredentials bool `json:"-"`
	// Config is the file as written, including inline keys, so it is deliberately
	// not serialised.
	Config string `json:"-"`
}
