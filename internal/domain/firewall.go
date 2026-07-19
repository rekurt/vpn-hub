package domain

// EgressDirect is the reserved egress name meaning "leave through the hub's own
// uplink". It is only ever selected by a profile that asks for it explicitly; it is
// never a fallback for a tunnel that went down.
const EgressDirect = "direct"

// FirewallPlan is the complete input to the packet filter. Every policy decision has
// already been made by the time a plan exists, so rendering it is a pure formatting
// step and the renderer needs no access to configuration.
type FirewallPlan struct {
	// IngressInterface carries client traffic into the hub.
	IngressInterface string `json:"ingress_interface"`
	// UplinkInterface is the host's default route interface, discovered at runtime.
	UplinkInterface string `json:"uplink_interface"`
	// ListenPort is the UDP port the ingress listens on.
	ListenPort uint16 `json:"listen_port"`
	// ManagementPort keeps administrative SSH reachable; without it a reconcile
	// would lock the operator out of the host.
	ManagementPort uint16 `json:"management_port"`

	ClientCIDR string `json:"client_cidr"`
	DNSAddress string `json:"dns_address"`

	// LinkBase is the range the veth links to tunnel namespaces are carved from.
	// Traffic a proxy originates arrives from it and has to be translated on the way
	// out, since the internet cannot answer a link address.
	LinkBase string `json:"link_base,omitempty"`

	// Internals are the private networks, each reached through its own tunnel. They
	// take priority over a device's default egress, which is what lets one
	// connection reach corporate resources and the internet at the same time.
	Internals []InternalNetwork `json:"internals,omitempty"`

	// Socks lists the SOCKS5 endpoints clients may reach.
	Socks []SocksEndpoint `json:"socks,omitempty"`

	// Egresses is ordered deterministically so an unchanged configuration renders
	// byte-identically.
	Egresses []EgressGroup `json:"egresses"`
}

// InternalNetwork is one private network and the tunnel that reaches it.
//
// Each gets its own address set rather than sharing one: a shared set can say that a
// destination is internal but not which tunnel owns it, and that is exactly the
// question routing has to answer.
type InternalNetwork struct {
	TunnelID string `json:"tunnel_id"`
	Mark     uint32 `json:"mark"`
	// Proxied means the same here as on an egress group: the process reaching the
	// provider runs inside the namespace, so its own connections are forwarded
	// through the main namespace and need a rule saying so. A private network can be
	// carried by sing-box or OpenVPN just as an egress can.
	Proxied bool `json:"proxied,omitempty"`
	// Interface carries traffic towards this network's namespace.
	Interface string `json:"interface"`
	// Routes are known statically from configuration. Addresses learned from DNS are
	// added to the same set at runtime.
	Routes []string `json:"routes,omitempty"`
	// Zones are the private domains resolved through this tunnel.
	Zones []string `json:"zones,omitempty"`
	// Resolvers answer for those zones and are themselves reached through the tunnel.
	Resolvers []string `json:"resolvers,omitempty"`
	// Clients are the device addresses allowed to reach this network. The tunnel's
	// allowed_devices decides it; with none set, every device is allowed. It is a
	// list of addresses rather than a subnet because the restriction is per device,
	// which is the only form the configuration can express.
	Clients []string `json:"clients,omitempty"`
}

// SocksEndpoint is one egress offered as a SOCKS5 proxy.
type SocksEndpoint struct {
	TunnelID string `json:"tunnel_id"`
	// Address is the hub's end of that tunnel's link, which is where a client aims.
	// The proxy itself listens on the other end; the hub's end forwards to it.
	Address string `json:"address"`
	// Interface is that link's host side. Traffic to the proxy is forwarded out of
	// it, which is what the packet filter matches on -- by the time the forward
	// chain sees the packet its destination has already been rewritten to the
	// namespace, so the address above no longer identifies it.
	Interface string `json:"interface"`
	Port      uint16 `json:"port"`
	// Clients are the device addresses allowed to use this endpoint. Without it the
	// proxy would be a way around the very choice it exists to offer: a device left
	// on `direct`, or excluded from this tunnel by allowed_devices, could point an
	// application at the port and leave through it anyway.
	Clients []string `json:"clients,omitempty"`
}

// EgressGroup binds a set of client addresses to one outbound path.
type EgressGroup struct {
	// ID is a tunnel ID, or EgressDirect.
	ID string `json:"id"`
	// Proxied marks a tunnel whose process runs inside its namespace, so its own
	// connections to the provider are forwarded through the main namespace rather
	// than originating there. A kernel tunnel keeps its socket in the main namespace
	// and needs no such rule.
	Proxied bool `json:"proxied,omitempty"`
	// Mark labels packets in the mangle hook so policy routing can act on them.
	Mark uint32 `json:"mark"`
	// Interface is where traffic for this group leaves the main namespace.
	Interface string `json:"interface"`
	// Addresses are bare client host addresses, without a prefix length.
	Addresses []string `json:"addresses"`
	// Clients are the devices allowed to use this tunnel at all, which is a wider
	// list than Addresses: a device may reach a provider through its SOCKS endpoint
	// without having chosen it as the default that Addresses records.
	Clients []string `json:"clients,omitempty"`
}
