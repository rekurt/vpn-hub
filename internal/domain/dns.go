package domain

// DNSZoneRoute sends one private domain to the resolvers inside its network.
type DNSZoneRoute struct {
	Zone string `json:"zone"`
	// Resolvers answer for this zone and live inside the network itself.
	Resolvers []string `json:"resolvers"`
	// ForwardAddress is the namespace-side veth address of a resolver that can reach
	// Resolvers from inside the private network. Empty means the hub resolver talks
	// to Resolvers directly.
	ForwardAddress string `json:"forward_address,omitempty"`
	// Set is the nftables set that learned addresses are added to, which is how a
	// name resolved here starts routing through the right tunnel.
	Set string `json:"set"`
}

// DNSPrivateResolver is a forwarding dnsmasq instance that runs inside a private
// network namespace. The hub-facing resolver cannot query private DNS servers from
// the main namespace without leaking or missing return routes; this instance makes
// the query from the tunnel where that DNS server actually lives.
type DNSPrivateResolver struct {
	TunnelID  string   `json:"tunnel_id"`
	Namespace string   `json:"namespace"`
	Address   string   `json:"address"`
	Resolvers []string `json:"resolvers"`
}

// DNSPlan is the hub's resolver policy.
//
// Two resolvers, not one. The hub-facing instance answers clients and sends private
// zones into their tunnels. Everything else is forwarded to a second instance running
// inside the default egress namespace, because a resolver in the main namespace would
// query upstream as the host: the provider would carry the traffic while public DNS
// still came from the hub's own address. That leak is invisible -- everything appears
// to work -- which is why it is handled here rather than left for later.
type DNSPlan struct {
	// ListenAddress is the hub's address on the client subnet.
	ListenAddress string `json:"listen_address"`
	ClientCIDR    string `json:"client_cidr"`

	Zones []DNSZoneRoute `json:"zones,omitempty"`
	// PrivateResolvers are per-private-network forwarders for Zones.
	PrivateResolvers []DNSPrivateResolver `json:"private_resolvers,omitempty"`

	// UpstreamNamespace runs the resolver that public queries are forwarded to. Empty
	// when every device leaves through the host uplink, where there is nothing to
	// hide behind.
	UpstreamNamespace string `json:"upstream_namespace,omitempty"`
	// UpstreamAddress is where that resolver listens, on the namespace end of its
	// veth link.
	UpstreamAddress string `json:"upstream_address,omitempty"`
	// PublicResolvers are the servers the upstream instance forwards to.
	PublicResolvers []string `json:"public_resolvers,omitempty"`
}
