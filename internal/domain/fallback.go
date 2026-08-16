package domain

// IngressFallback describes the alternative ways in, for networks that block the
// hub's ordinary UDP ingress.
//
// Both are off unless configured. They open a port on the hub, and a listener
// nobody asked for is attack surface rather than a feature.
type IngressFallback struct {
	// UDP443 redirects UDP/443 arriving on the uplink to the ingress port, for
	// networks that block UDP/51820 specifically rather than UDP as such. The
	// client keeps its ordinary profile with the port changed.
	UDP443 bool `mapstructure:"udp443" json:"udp443,omitempty"`
	// Reality is a TCP/443 VLESS listener for networks that discard UDP entirely.
	Reality RealityFallback `mapstructure:"reality" json:"reality,omitempty"`
}

// RealityFallback configures the TCP ingress of last resort.
type RealityFallback struct {
	Enabled bool `mapstructure:"enabled" json:"enabled,omitempty"`
	// ServerName is the real TLS 1.3 site the handshake mimics, and which
	// unauthenticated connections are handed to. It has to be a site that is
	// plausible to reach from this hub and that is not the hub itself.
	ServerName string `mapstructure:"server_name" json:"server_name,omitempty"`
}

// RealityPort is fixed at 443: the whole point is to be indistinguishable from
// ordinary HTTPS, which any other port defeats.
const RealityPort uint16 = 443

// RealityUser is one device admitted through the fallback.
type RealityUser struct {
	DeviceID string `json:"device_id"`
	// UUID authenticates the device and is derived from the hub's private key, so
	// it is deliberately not serialised -- same reasoning as ProxyTunnel.UUID.
	UUID string `json:"-"`
	// Mark is the fwmark of the device's egress tunnel, or zero for direct. The
	// listener sets it on the connections it opens for this user, and the policy
	// routing the reconciler already installs sends them into that tunnel.
	Mark uint32 `json:"mark,omitempty"`
}

// RealityIngressSpec is the complete input to the fallback listener. Like every
// other spec it is compiled from the revision, so the adapter formats and executes
// but decides nothing.
type RealityIngressSpec struct {
	// Enabled false is a meaningful spec: it asks for the listener to be gone.
	Enabled    bool   `json:"enabled"`
	Port       uint16 `json:"port"`
	ServerName string `json:"server_name"`
	// PrivateKey stays out of the serialised form; it lives on the host.
	PrivateKey string `json:"-"`
	ShortID    string `json:"short_id"`
	// DNSAddress is the hub's resolver, so names asked for over this path resolve
	// through the same split DNS as everything else -- including the private zones
	// whose answers populate the packet filter's sets.
	DNSAddress string        `json:"dns_address"`
	Users      []RealityUser `json:"users,omitempty"`
}
