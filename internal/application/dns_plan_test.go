package application

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func dnsFixture(t *testing.T) (domain.DesiredState, domain.FirewallPlan, []domain.EgressSpec) {
	t.Helper()
	state, tunnels := egressState(t)
	state.Tunnels = append(state.Tunnels, domain.Tunnel{
		ID: "corp-a", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork,
		Source:     domain.TunnelSource{Kind: domain.SourceConfig, Value: "corp-a.conf"},
		Routes:     []string{"10.20.0.0/16"},
		DNSServers: []string{"10.20.0.53"},
		DNSZones:   []string{"corp.internal"},
	})
	tunnels["corp-a"] = tunnels["corp-wg"]

	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := BuildEgressSpecs(state, plan, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	return state, plan, specs
}

func TestPrivateZonesResolveThroughTheirOwnTunnel(t *testing.T) {
	t.Parallel()
	state, plan, specs := dnsFixture(t)

	dns, err := BuildDNSPlan(state, plan, specs)
	if err != nil {
		t.Fatalf("BuildDNSPlan: %v", err)
	}
	if len(dns.Zones) != 1 {
		t.Fatalf("expected one zone, got %+v", dns.Zones)
	}
	zone := dns.Zones[0]
	if zone.Zone != "corp.internal" || len(zone.Resolvers) != 1 || zone.Resolvers[0] != "10.20.0.53" {
		t.Errorf("zone = %+v", zone)
	}
	if zone.ForwardAddress == "" {
		t.Errorf("ForwardAddress is empty; private DNS would be queried from the main namespace")
	}
	if len(dns.PrivateResolvers) != 1 {
		t.Fatalf("expected one private resolver, got %+v", dns.PrivateResolvers)
	}
	resolver := dns.PrivateResolvers[0]
	if resolver.TunnelID != "corp-a" || resolver.Namespace == "" || resolver.Address != zone.ForwardAddress {
		t.Errorf("private resolver = %+v, zone = %+v", resolver, zone)
	}
	// Without the set, a private name would resolve correctly and then route out of
	// the internet path.
	if zone.Set != "internal_corp_a" {
		t.Errorf("Set = %q, want the private network's own set", zone.Set)
	}
}

// A resolver in the main namespace would query upstream as the host, so the provider
// would carry the traffic while public DNS still came from the hub's address.
func TestPublicQueriesLeaveThroughTheDefaultEgress(t *testing.T) {
	t.Parallel()
	state, plan, specs := dnsFixture(t)

	dns, err := BuildDNSPlan(state, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	if dns.UpstreamNamespace == "" {
		t.Fatal("public queries must be forwarded into an egress namespace")
	}
	if dns.UpstreamAddress == "" {
		t.Fatal("the upstream resolver needs an address to listen on")
	}
	if strings.Contains(dns.UpstreamNamespace, "corp-a") {
		t.Error("public queries must not go through a private network")
	}
}

// With everyone on direct there is no namespace to hide in, and pretending otherwise
// would be worse than saying so.
func TestDirectOnlyHubResolvesForItself(t *testing.T) {
	t.Parallel()
	state, plan, specs := dnsFixture(t)
	for index := range state.Devices {
		state.Devices[index].Egress = domain.EgressDirect
	}

	dns, err := BuildDNSPlan(state, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	if dns.UpstreamNamespace != "" {
		t.Errorf("expected no upstream namespace, got %q", dns.UpstreamNamespace)
	}
	if len(dns.PublicResolvers) == 0 {
		t.Error("the hub still needs somewhere to send public queries")
	}
}

// Forwarding a private zone to a public resolver would send internal names to the
// internet, so a zone without a resolver is a configuration error.
func TestZoneWithoutAResolverIsRejected(t *testing.T) {
	t.Parallel()
	state, plan, specs := dnsFixture(t)
	for index := range plan.Internals {
		plan.Internals[index].Resolvers = nil
	}

	if _, err := BuildDNSPlan(state, plan, specs); err == nil {
		t.Fatal("expected a zone with no resolver to be refused")
	}
}

func TestDNSPlanIsDeterministic(t *testing.T) {
	t.Parallel()
	state, plan, specs := dnsFixture(t)
	first, err := BuildDNSPlan(state, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDNSPlan(state, plan, specs)
	if err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, first) != mustJSON(t, second) {
		t.Fatal("two builds of the same revision disagreed")
	}
}
