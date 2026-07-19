package application

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func planState() domain.DesiredState {
	return domain.DesiredState{
		Hub: domain.Hub{
			Endpoint:   "vpn.example.test:51820",
			ClientCIDR: "10.80.0.0/24",
			DNSAddress: "10.80.0.1",
		},
		Devices: []domain.DeployedDevice{
			{ID: "macbook", Address: "10.80.0.2/32", Egress: domain.EgressDirect},
			{ID: "phone", Address: "10.80.0.3/32", Egress: "corp-wg"},
		},
		Tunnels: []domain.Tunnel{
			{ID: "corp-wg", Role: domain.RolePrivateNetwork, Routes: []string{"10.20.0.0/16"}},
			{ID: "vpn-out", Role: domain.RoleEgress, Routes: []string{"10.30.0.0/16"}},
		},
	}
}

func TestBuildFirewallPlan(t *testing.T) {
	t.Parallel()
	plan, err := BuildFirewallPlan(planState(), "eth0")
	if err != nil {
		t.Fatalf("BuildFirewallPlan: %v", err)
	}

	if plan.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", plan.ListenPort)
	}
	if plan.ManagementPort == 0 {
		t.Error("ManagementPort must be set or the ruleset locks the operator out")
	}
	// direct, corp-wg (chosen by a device) and vpn-out (chosen by nobody).
	if len(plan.Egresses) != 3 {
		t.Fatalf("expected three egress groups, got %d", len(plan.Egresses))
	}

	// Only private-network tunnels become internal networks; an egress tunnel's
	// routes are not reachable that way.
	if len(plan.Internals) != 1 || plan.Internals[0].TunnelID != "corp-wg" {
		t.Fatalf("Internals = %+v, want just the private-network tunnel", plan.Internals)
	}
	if got := plan.Internals[0].Routes; len(got) != 1 || got[0] != "10.20.0.0/16" {
		t.Errorf("Routes = %v, want the configured subnet", got)
	}

	// Internal marks must not collide with egress marks, or traffic is routed by
	// whichever table happens to answer for that mark.
	used := map[uint32]string{}
	for _, group := range plan.Egresses {
		used[group.Mark] = group.ID
	}
	for _, network := range plan.Internals {
		if previous, clash := used[network.Mark]; clash {
			t.Errorf("mark %#x is shared by %s and %s", network.Mark, previous, network.TunnelID)
		}
		used[network.Mark] = network.TunnelID
	}
}

// direct must keep its mark no matter how the tunnel list changes, because it is the
// egress that has to keep working while others are edited.
func TestDirectKeepsAStableMark(t *testing.T) {
	t.Parallel()
	before, err := BuildFirewallPlan(planState(), "eth0")
	if err != nil {
		t.Fatal(err)
	}

	state := planState()
	state.Devices = append(state.Devices,
		domain.DeployedDevice{ID: "extra", Address: "10.80.0.9/32", Egress: "aaa-first"})
	after, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}

	if markOf(t, before, domain.EgressDirect) != markOf(t, after, domain.EgressDirect) {
		t.Fatal("adding an alphabetically earlier egress renumbered direct")
	}
}

func TestBuildFirewallPlanIsDeterministic(t *testing.T) {
	t.Parallel()
	first, err := BuildFirewallPlan(planState(), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildFirewallPlan(planState(), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, first) != mustJSON(t, second) {
		t.Fatal("two builds of the same state disagreed")
	}
}

// nftables sets of type ipv4_addr reject a prefix length.
func TestAddressesAreRenderedWithoutPrefixLength(t *testing.T) {
	t.Parallel()
	plan, err := BuildFirewallPlan(planState(), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range plan.Egresses {
		for _, address := range group.Addresses {
			if got := address; got != "10.80.0.2" && got != "10.80.0.3" {
				t.Errorf("unexpected address %q", got)
			}
		}
	}
}

// The resolver for a private zone has to reach that zone's tunnel, so it joins the
// set -- unless a declared subnet already covers it, since nftables interval sets
// refuse overlapping entries.
func TestResolversJoinTheSetOnlyWhenNotAlreadyCovered(t *testing.T) {
	t.Parallel()
	state := planState()
	state.Tunnels[0].DNSServers = []string{"10.20.0.53", "192.168.9.53"}
	state.Tunnels[0].DNSZones = []string{"corp.internal"}

	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatalf("BuildFirewallPlan: %v", err)
	}
	if len(plan.Internals) != 1 {
		t.Fatalf("expected one private network, got %+v", plan.Internals)
	}

	routes := plan.Internals[0].Routes
	joined := strings.Join(routes, " ")
	if !strings.Contains(joined, "192.168.9.53/32") {
		t.Errorf("a resolver outside the declared subnets must be routed too: %v", routes)
	}
	if strings.Contains(joined, "10.20.0.53/32") {
		t.Errorf("a resolver already inside 10.20.0.0/16 must not be added again: %v", routes)
	}
}

func TestBuildFirewallPlanRejectsBadInput(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*domain.DesiredState)
		uplink string
	}{
		"missing uplink":       {func(*domain.DesiredState) {}, ""},
		"endpoint has no port": {func(s *domain.DesiredState) { s.Hub.Endpoint = "vpn.example.test" }, "eth0"},
		"port out of range":    {func(s *domain.DesiredState) { s.Hub.Endpoint = "vpn.example.test:0" }, "eth0"},
		"bad address": {func(s *domain.DesiredState) {
			s.Devices[0].Address = "not-an-address"
		}, "eth0"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := planState()
			test.mutate(&state)
			if _, err := BuildFirewallPlan(state, test.uplink); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func markOf(t *testing.T, plan domain.FirewallPlan, id string) uint32 {
	t.Helper()
	for _, group := range plan.Egresses {
		if group.ID == id {
			return group.Mark
		}
	}
	t.Fatalf("egress %q not found in plan", id)
	return 0
}

// An egress tunnel nobody has chosen as their default still has to be built. It is
// what a SOCKS endpoint offers, and what `device set-egress` switches onto; if it
// only appeared once someone selected it, the tunnel would be configured, enabled,
// valid -- and silently absent from the host.
func TestUnchosenEgressStillGetsAGroup(t *testing.T) {
	t.Parallel()
	state := planState()
	state.Devices = []domain.DeployedDevice{
		{ID: "macbook", Address: "10.80.0.2/32", Egress: domain.EgressDirect},
	}

	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatalf("BuildFirewallPlan: %v", err)
	}

	var found *domain.EgressGroup
	for index, group := range plan.Egresses {
		if group.ID == "vpn-out" {
			found = &plan.Egresses[index]
		}
	}
	if found == nil {
		t.Fatalf("the unchosen egress is missing; groups: %+v", plan.Egresses)
	}
	// No device sends its default traffic there, so its set stays empty: the tunnel
	// exists and steers nothing until something asks for it by name.
	if len(found.Addresses) != 0 {
		t.Errorf("Addresses = %v, want none until a device chooses it", found.Addresses)
	}
	if found.Mark == 0 {
		t.Error("the group needs a mark, or its namespace cannot be routed to")
	}
}

// A disabled tunnel is excluded from the revision entirely, so it must not reappear
// here -- otherwise "disabled" would mean "built but unused".
func TestDisabledEgressGetsNoGroup(t *testing.T) {
	t.Parallel()
	state := planState()
	state.Devices = []domain.DeployedDevice{
		{ID: "macbook", Address: "10.80.0.2/32", Egress: domain.EgressDirect},
	}
	state.Tunnels = []domain.Tunnel{state.Tunnels[0]}

	plan, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatalf("BuildFirewallPlan: %v", err)
	}
	for _, group := range plan.Egresses {
		if group.ID == "vpn-out" {
			t.Fatalf("a tunnel outside the revision was built anyway: %+v", group)
		}
	}
}
