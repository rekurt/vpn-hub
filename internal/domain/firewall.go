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

	// InternalRoutes are destinations reached through private-network tunnels. They
	// take priority over a profile's default egress.
	InternalRoutes []string `json:"internal_routes,omitempty"`

	// Egresses is ordered deterministically so an unchanged configuration renders
	// byte-identically.
	Egresses []EgressGroup `json:"egresses"`
}

// EgressGroup binds a set of client addresses to one outbound path.
type EgressGroup struct {
	// ID is a tunnel ID, or EgressDirect.
	ID string `json:"id"`
	// Mark labels packets in the mangle hook so policy routing can act on them.
	Mark uint32 `json:"mark"`
	// Interface is where traffic for this group leaves the main namespace.
	Interface string `json:"interface"`
	// Addresses are bare client host addresses, without a prefix length.
	Addresses []string `json:"addresses"`
}
