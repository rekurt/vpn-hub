package application

import (
	"reflect"
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

// Every device must resolve public names through the same egress as its traffic.
// Sharing one busiest-egress resolver leaks the other devices' DNS to that provider.
func TestPublicQueriesFollowEachDevicesEgress(t *testing.T) {
	t.Parallel()
	state := domain.DesiredState{Hub: domain.Hub{
		ClientCIDR: "10.80.0.0/24", DNSAddress: "10.80.0.1",
	}, Devices: []domain.DeployedDevice{
		{ID: "direct-device", Address: "10.80.0.2/32", Egress: domain.EgressDirect},
		{ID: "wg-device", Address: "10.80.0.3/32", Egress: "wg-nl"},
		{ID: "xray-device", Address: "10.80.0.4/32", Egress: "xray-de"},
	}}
	plan := domain.FirewallPlan{Egresses: []domain.EgressGroup{
		{ID: "xray-de", Addresses: []string{"10.80.0.4"}},
		{ID: domain.EgressDirect, Addresses: []string{"10.80.0.2"}},
		{ID: "wg-nl", Addresses: []string{"10.80.0.3"}},
	}}
	specs := []domain.EgressSpec{
		{TunnelID: "xray-de", Namespace: "vpn-hub-xray-de", HostAddress: "10.90.0.5/30", PeerAddress: "10.90.0.6/30"},
		{TunnelID: "wg-nl", Namespace: "vpn-hub-wg-nl", HostAddress: "10.90.0.1/30", PeerAddress: "10.90.0.2/30"},
	}

	dns, err := BuildDNSPlan(state, plan, specs)
	if err != nil {
		t.Fatalf("BuildDNSPlan: %v", err)
	}
	want := []domain.DNSEgressResolver{
		{
			EgressID: domain.EgressDirect, ClientAddresses: []string{"10.80.0.2"},
			HubAddress: "10.80.0.1", PublicResolvers: []string{"1.1.1.1", "9.9.9.9"},
		},
		{
			EgressID: "wg-nl", ClientAddresses: []string{"10.80.0.3"},
			HubAddress: "10.90.0.1", Namespace: "vpn-hub-wg-nl", NamespaceAddress: "10.90.0.2",
			PublicResolvers: []string{"1.1.1.1", "9.9.9.9"},
		},
		{
			EgressID: "xray-de", ClientAddresses: []string{"10.80.0.4"},
			HubAddress: "10.90.0.5", Namespace: "vpn-hub-xray-de", NamespaceAddress: "10.90.0.6",
			PublicResolvers: []string{"1.1.1.1", "9.9.9.9"},
		},
	}
	if !reflect.DeepEqual(dns.EgressResolvers, want) {
		t.Fatalf("EgressResolvers = %#v, want %#v", dns.EgressResolvers, want)
	}
}

func TestAssignedTunnelWithoutAnEgressSpecIsRejected(t *testing.T) {
	t.Parallel()
	state, plan, specs := dnsFixture(t)
	remaining := specs[:0]
	for _, spec := range specs {
		if spec.TunnelID != "corp-wg" {
			remaining = append(remaining, spec)
		}
	}

	if _, err := BuildDNSPlan(state, plan, remaining); err == nil {
		t.Fatal("an assigned tunnel without a spec must fail closed")
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
