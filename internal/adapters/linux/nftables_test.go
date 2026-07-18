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
	plan.InternalRoutes = []string{"10.20.0.0/16"}
	plan.Egresses = append(plan.Egresses, domain.EgressGroup{
		ID:        "corp-wg",
		Mark:      0x101,
		Interface: "vh-corp-wg",
		Addresses: []string{"10.80.0.4"},
	})
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
