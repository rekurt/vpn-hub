package application

import (
	"net/netip"
	"testing"

	"vpn-hub/internal/domain"
)

func egressState(t *testing.T) (domain.DesiredState, map[string]domain.Upstream) {
	t.Helper()
	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, clientPublic, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	state := domain.DesiredState{
		Hub: domain.Hub{
			Endpoint:   "vpn.example.test:51820",
			ClientCIDR: "10.80.0.0/24",
			DNSAddress: "10.80.0.1",
		},
		Devices: []domain.DeployedDevice{
			{ID: "laptop", Address: "10.80.0.2/32", PublicKey: clientPublic, Egress: domain.EgressDirect},
			{ID: "phone", Address: "10.80.0.3/32", PublicKey: clientPublic, Egress: "corp-wg"},
			{ID: "tablet", Address: "10.80.0.4/32", PublicKey: clientPublic, Egress: "alt-wg"},
		},
		Tunnels: []domain.Tunnel{
			{ID: "corp-wg", Type: domain.TunnelWireGuard, Role: domain.RoleEgress,
				Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "corp.conf"}},
			{ID: "alt-wg", Type: domain.TunnelWireGuard, Role: domain.RoleEgress,
				Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "alt.conf"}},
		},
	}

	upstream := domain.Upstream{
		Type: domain.TunnelWireGuard,
		WireGuard: domain.WireGuardTunnel{
			PrivateKey: privateKey,
			Addresses:  []string{"10.7.0.5/32"},
			Peer: domain.WireGuardPeer{
				PublicKey: publicKey, Endpoint: "provider.example:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
			},
		},
	}
	return state, map[string]domain.Upstream{"corp-wg": upstream, "alt-wg": upstream}
}

func buildEgress(t *testing.T) []domain.EgressSpec {
	t.Helper()
	state, tunnels := egressState(t)
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := BuildEgressSpecs(state, plan, tunnels)
	if err != nil {
		t.Fatalf("BuildEgressSpecs: %v", err)
	}
	return specs
}

func TestEachTunnelGetsItsOwnNamespaceAndLink(t *testing.T) {
	t.Parallel()
	specs := buildEgress(t)
	if len(specs) != 2 {
		t.Fatalf("expected two egress specs, got %d", len(specs))
	}

	seen := map[string]string{}
	for _, spec := range specs {
		for label, value := range map[string]string{
			"namespace": spec.Namespace, "host veth": spec.HostVeth,
			"host address": spec.HostAddress, "peer address": spec.PeerAddress,
		} {
			if previous, clash := seen[value]; clash {
				t.Fatalf("%s %q is shared with %s", label, value, previous)
			}
			seen[value] = spec.TunnelID + " " + label
		}
	}
}

// The two ends of a link must sit in the same /30 and differ, or the namespaces
// cannot talk to the host.
func TestLinkEndsArePairedCorrectly(t *testing.T) {
	t.Parallel()
	for _, spec := range buildEgress(t) {
		host, err := netip.ParsePrefix(spec.HostAddress)
		if err != nil {
			t.Fatalf("%s: host address %q: %v", spec.TunnelID, spec.HostAddress, err)
		}
		peer, err := netip.ParsePrefix(spec.PeerAddress)
		if err != nil {
			t.Fatalf("%s: peer address %q: %v", spec.TunnelID, spec.PeerAddress, err)
		}
		if host.Bits() != 30 || peer.Bits() != 30 {
			t.Errorf("%s: link should be a /30, got /%d and /%d", spec.TunnelID, host.Bits(), peer.Bits())
		}
		if host.Masked() != peer.Masked() {
			t.Errorf("%s: %s and %s are not in the same subnet", spec.TunnelID, host, peer)
		}
		if host.Addr() == peer.Addr() {
			t.Errorf("%s: both ends have address %s", spec.TunnelID, host.Addr())
		}
	}
}

// Marks and tables have to line up with the firewall plan, or traffic is marked for a
// table that routes somewhere else.
func TestMarksMatchTheFirewallPlan(t *testing.T) {
	t.Parallel()
	state, tunnels := egressState(t)
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := BuildEgressSpecs(state, plan, tunnels)
	if err != nil {
		t.Fatal(err)
	}

	marks := map[string]uint32{}
	for _, group := range plan.Egresses {
		marks[group.ID] = group.Mark
	}
	tables := map[int]string{}
	for _, spec := range specs {
		if marks[spec.TunnelID] != spec.Mark {
			t.Errorf("%s: mark %#x does not match the plan's %#x", spec.TunnelID, spec.Mark, marks[spec.TunnelID])
		}
		if previous, clash := tables[spec.RouteTable]; clash {
			t.Errorf("route table %d is shared by %s and %s", spec.RouteTable, previous, spec.TunnelID)
		}
		tables[spec.RouteTable] = spec.TunnelID
		if spec.HostVeth != EgressInterface(spec.TunnelID) {
			t.Errorf("%s: veth %q does not match the name the firewall plan uses", spec.TunnelID, spec.HostVeth)
		}
	}
}

// The layout is derived, not stored, so an agent restart must not renumber a running
// hub.
func TestLayoutIsReproducible(t *testing.T) {
	t.Parallel()
	first, second := buildEgress(t), buildEgress(t)
	if len(first) != len(second) {
		t.Fatalf("built %d specs and then %d", len(first), len(second))
	}
	for index := range first {
		a, b := first[index], second[index]
		if a.Namespace != b.Namespace || a.HostAddress != b.HostAddress ||
			a.PeerAddress != b.PeerAddress || a.Mark != b.Mark || a.RouteTable != b.RouteTable {
			t.Fatalf("%s was laid out differently on a second build:\n%+v\n%+v", a.TunnelID, a, b)
		}
	}
}

func TestDirectIsNotAnEgressNamespace(t *testing.T) {
	t.Parallel()
	for _, spec := range buildEgress(t) {
		if spec.TunnelID == domain.EgressDirect {
			t.Fatal("direct leaves through the host uplink and needs no namespace")
		}
	}
}

func TestBuildEgressSpecsRejectsProtocolsWithoutADriver(t *testing.T) {
	t.Parallel()
	state, tunnels := egressState(t)
	state.Tunnels[0].Type = domain.TunnelOpenVPN
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildEgressSpecs(state, plan, tunnels); err == nil {
		t.Fatal("expected a tunnel type with no driver to be refused rather than pretended")
	}
}

// A proxy tunnel gets a namespace like any other, but its device is the one sing-box
// creates rather than a kernel interface.
func TestProxyTunnelsGetTheirOwnDevice(t *testing.T) {
	t.Parallel()
	state, tunnels := egressState(t)
	state.Tunnels[0].Type = domain.TunnelXray
	state.Tunnels[0].Source = domain.TunnelSource{Kind: domain.SourceConfig, Value: "corp.txt"}
	tunnels["corp-wg"] = domain.Upstream{
		Type:  domain.TunnelXray,
		Proxy: domain.ProxyTunnel{Protocol: "vless", Server: "node.example", Port: 443, UUID: "u"},
	}

	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := BuildEgressSpecs(state, plan, tunnels)
	if err != nil {
		t.Fatalf("BuildEgressSpecs: %v", err)
	}
	for _, spec := range specs {
		if spec.TunnelID != "corp-wg" {
			continue
		}
		if spec.Type != domain.TunnelXray {
			t.Errorf("Type = %q", spec.Type)
		}
		if spec.Interface != "sb0" {
			t.Errorf("Interface = %q, want the proxy device", spec.Interface)
		}
		if spec.Proxy.Server != "node.example" {
			t.Errorf("the proxy configuration did not reach the spec: %+v", spec.Proxy)
		}
		return
	}
	t.Fatal("the proxy tunnel produced no spec")
}

func TestBuildEgressSpecsRequiresAnUpstreamConfiguration(t *testing.T) {
	t.Parallel()
	state, _ := egressState(t)
	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildEgressSpecs(state, plan, nil); err == nil {
		t.Fatal("expected a missing upstream configuration to be an error")
	}
}
