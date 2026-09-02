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

// DNSEgressResolver is the resolver pair serving clients assigned to one egress.
type DNSEgressResolver struct {
	EgressID         string   `json:"egress_id"`
	ClientAddresses  []string `json:"client_addresses"`
	HubAddress       string   `json:"hub_address"`
	Namespace        string   `json:"namespace,omitempty"`
	NamespaceAddress string   `json:"namespace_address,omitempty"`
	PublicResolvers  []string `json:"public_resolvers,omitempty"`
}

// DNSPlan is the hub's resolver policy.
//
// Every assigned egress has a main-namespace resolver. A tunneled egress also has a
// namespace resolver, so public DNS follows the device's traffic path.
type DNSPlan struct {
	ClientCIDR string `json:"client_cidr"`

	Zones []DNSZoneRoute `json:"zones,omitempty"`
	// PrivateResolvers are per-private-network forwarders for Zones.
	PrivateResolvers []DNSPrivateResolver `json:"private_resolvers,omitempty"`

	EgressResolvers []DNSEgressResolver `json:"egress_resolvers"`
}
