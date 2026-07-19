package linux

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

var update = flag.Bool("update", false, "rewrite golden files")

func goldenTest(t *testing.T, name string, plan domain.FirewallPlan) string {
	t.Helper()
	rendered := RenderRuleset(plan)
	path := filepath.Join("testdata", name+".nft")

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return rendered
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run `go test ./internal/adapters/linux -update`): %v", err)
	}
	if rendered != string(want) {
		t.Errorf("ruleset does not match %s\n--- got ---\n%s", path, rendered)
	}
	return rendered
}

// directOnlyPlan is the M1 shape: one device leaving through the hub's own uplink.
func directOnlyPlan() domain.FirewallPlan {
	return domain.FirewallPlan{
		IngressInterface: "awg0",
		UplinkInterface:  "eth0",
		ListenPort:       51820,
		ManagementPort:   22,
		ClientCIDR:       "10.80.0.0/24",
		DNSAddress:       "10.80.0.1",
		Egresses: []domain.EgressGroup{{
			ID:        domain.EgressDirect,
			Mark:      0x100,
			Interface: "eth0",
			Addresses: []string{"10.80.0.2", "10.80.0.3"},
		}},
	}
}

func TestRenderDirectOnly(t *testing.T) {
	t.Parallel()
	goldenTest(t, "direct-only", directOnlyPlan())
}

func TestRenderWithTunnelAndInternalRoutes(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Egresses = append(plan.Egresses, domain.EgressGroup{
		ID:        "provider-nl",
		Mark:      0x101,
		Interface: "vh-provider-nl",
		Addresses: []string{"10.80.0.4"},
	})
	plan.Internals = []domain.InternalNetwork{{
		TunnelID:  "corp-a",
		Mark:      0x102,
		Interface: "vh-corp-a",
		// The resolver at 10.20.0.53 is inside the subnet, so it needs no entry of
		// its own; an interval set rejects overlapping ones anyway.
		Routes:    []string{"10.20.0.0/16"},
		Zones:     []string{"corp.internal"},
		Resolvers: []string{"10.20.0.53"},
	}}
	goldenTest(t, "tunnel-and-internal", plan)
}

// The kill switch is the forward chain's policy rather than an explicit rule, so it
// is worth asserting directly: a refactor that flipped it to accept would leave every
// golden file looking plausible.
func TestForwardChainDefaultsToDrop(t *testing.T) {
	t.Parallel()
	rendered := RenderRuleset(directOnlyPlan())
	if !strings.Contains(rendered, "type filter hook forward priority filter; policy drop;") {
		t.Fatal("forward chain must default to drop")
	}
	if !strings.Contains(rendered, "type filter hook input priority filter; policy drop;") {
		t.Fatal("input chain must default to drop")
	}
}

// Without this the operator loses the host the moment the agent applies a ruleset.
func TestManagementPortStaysOpen(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.ManagementPort = 2222
	if !strings.Contains(RenderRuleset(plan), "tcp dport 2222 accept") {
		t.Fatal("the management port must be reachable")
	}
}

// A private destination must keep its own mark: setting a mark does not stop rule
// evaluation, so without the return the default-egress rule would overwrite it and
// corporate traffic would leave through the internet path instead.
func TestInternalNetworksOutrankTheDefaultEgress(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Internals = []domain.InternalNetwork{{
		TunnelID: "corp-a", Mark: 0x102, Interface: "vh-corp-a",
		Routes: []string{"10.20.0.0/16"},
	}}
	rendered := RenderRuleset(plan)

	internal := strings.Index(rendered, "ip daddr @internal_corp_a")
	egress := strings.Index(rendered, "ip saddr @client_direct meta mark")
	if internal < 0 || egress < 0 {
		t.Fatalf("both rules must be present:\n%s", rendered)
	}
	if internal > egress {
		t.Error("the private-network rule must be evaluated first")
	}
	if !strings.Contains(rendered, "@internal_corp_a meta mark set 0x00000102 ct mark set meta mark return") {
		t.Errorf("the private-network rule must end the chain:\n%s", rendered)
	}
}

// Each private network needs its own set: a shared one can say a destination is
// internal but not which tunnel owns it.
func TestEachPrivateNetworkHasItsOwnSet(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Internals = []domain.InternalNetwork{
		{TunnelID: "corp-a", Mark: 0x102, Interface: "vh-corp-a", Routes: []string{"10.20.0.0/16"}},
		{TunnelID: "corp-b", Mark: 0x103, Interface: "vh-corp-b", Routes: []string{"10.50.0.0/16"}},
	}
	rendered := RenderRuleset(plan)

	for _, wanted := range []string{
		"set internal_corp_a", "set internal_corp_b",
		`ip daddr @internal_corp_a oifname "vh-corp-a" accept`,
		`ip daddr @internal_corp_b oifname "vh-corp-b" accept`,
	} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q:\n%s", wanted, rendered)
		}
	}
}

// dnsmasq adds resolved addresses to these sets, which needs interval flags.
func TestInternalSetsAcceptLearnedAddresses(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Internals = []domain.InternalNetwork{{TunnelID: "corp-a", Mark: 0x102, Interface: "vh-corp-a"}}
	rendered := RenderRuleset(plan)

	if !strings.Contains(rendered, "flags interval") {
		t.Error("the set must take prefixes as well as the addresses DNS supplies")
	}
	// An empty set is legitimate: a zone with no static routes is filled entirely
	// from DNS answers.
	if strings.Contains(rendered, "elements = {  }") {
		t.Errorf("an empty set should omit elements entirely:\n%s", rendered)
	}
}

func TestRulesetReplacesOnlyItsOwnTable(t *testing.T) {
	t.Parallel()
	rendered := RenderRuleset(directOnlyPlan())
	if !strings.Contains(rendered, "table inet vpn_hub\ndelete table inet vpn_hub") {
		t.Fatal("expected the create-then-delete idiom that scopes the replacement")
	}
	if strings.Contains(rendered, "flush ruleset") {
		t.Fatal("flushing the whole ruleset would destroy unrelated tables")
	}
}
