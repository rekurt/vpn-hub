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
	// Interface carries traffic towards this network's namespace.
	Interface string `json:"interface"`
	// Routes are known statically from configuration. Addresses learned from DNS are
	// added to the same set at runtime.
	Routes []string `json:"routes,omitempty"`
	// Zones are the private domains resolved through this tunnel.
	Zones []string `json:"zones,omitempty"`
	// Resolvers answer for those zones and are themselves reached through the tunnel.
	Resolvers []string `json:"resolvers,omitempty"`
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
}
