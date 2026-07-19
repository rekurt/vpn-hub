package linux

import (
	"context"
	"errors"
	"flag"
	"fmt"
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

// A SOCKS endpoint is a second way into a tunnel, so it needs its own hole in a
// chain whose policy is drop. The rule is easy to lose -- it once was -- and losing
// it is silent: the proxy still listens, the connection just never arrives.
func TestRenderSocksEndpoint(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Socks = []domain.SocksEndpoint{
		{TunnelID: "corp", Address: "10.90.0.1", Interface: "vh-corp", Port: 11080},
	}
	ruleset := goldenTest(t, "socks-endpoint", plan)

	rule := `iifname "awg0" ip saddr @allowed_corp oifname "vh-corp" tcp dport 11080 accept`
	if !strings.Contains(ruleset, rule) {
		t.Fatalf("no forward rule for the endpoint:\n%s", ruleset)
	}
	// In the forward chain, not input: the destination is rewritten to the namespace
	// before the routing decision, so these packets are forwarded, never delivered
	// locally. An input rule would look right and pass nothing.
	forward := ruleset[strings.Index(ruleset, "chain forward"):strings.Index(ruleset, "chain input")]
	if !strings.Contains(forward, rule) {
		t.Errorf("the rule is outside the forward chain:\n%s", ruleset)
	}
}

// The sets in this table are not derived from the plan alone: dnsmasq adds the
// addresses it resolves for a private zone. Replacing the table throws those away,
// so replacing it on a timer meant a private address forgotten mid-session matched
// the default egress rule instead and left through the internet provider.
func TestAnUnchangedRulesetIsLeftAlone(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	host := &fakeHost{replies: map[string]string{
		"nft -j list table inet vpn_hub": fmt.Sprintf(
			`{"nftables":[{"table":{"comment":"vpn-hub:%s"}}]}`, Fingerprint(plan)),
	}}

	rebuilt, err := (NFTables{Run: host.run, RuntimeDir: t.TempDir()}).Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rebuilt {
		t.Error("Apply reported a rebuild it did not need to do")
	}
}

// When the ruleset genuinely changed it must still be replaced, and the caller has
// to learn that the sets are now empty.
func TestAChangedRulesetIsReplacedAndReported(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{
		"nft -j list table inet vpn_hub": `{"nftables":[{"table":{"comment":"vpn-hub:something-else"}}]}`,
	}}

	rebuilt, err := (NFTables{Run: host.run, RuntimeDir: t.TempDir()}).Apply(context.Background(), directOnlyPlan())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !rebuilt {
		t.Error("a differing ruleset was not replaced, or the replacement went unreported")
	}
	if !host.ran("nft -f ") {
		t.Errorf("the ruleset was never loaded; commands: %v", host.commands)
	}
}

// The round trip that drift detection rests on: what the renderer embeds is what
// the parser reads back. Nothing tested it, so a change to either side would have
// broken drift detection silently -- and a hub that cannot see drift reports
// convergence either way.
func TestTheFingerprintSurvivesTheRoundTrip(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	ruleset := RenderRuleset(plan)

	marker := `comment "vpn-hub:` + Fingerprint(plan) + `"`
	if !strings.Contains(ruleset, marker) {
		t.Fatalf("the rendered table does not carry its own fingerprint:\n%s", ruleset)
	}

	// The shape nft actually reports it back in.
	parsed, err := parseFingerprint(fmt.Sprintf(
		`{"nftables":[{"metainfo":{"version":"1.0.9"}},{"table":{"family":"inet","name":"vpn_hub","handle":1,"comment":"vpn-hub:%s"}}]}`,
		Fingerprint(plan)))
	if err != nil {
		t.Fatalf("parseFingerprint: %v", err)
	}
	if parsed != Fingerprint(plan) {
		t.Errorf("parsed %q, want %q", parsed, Fingerprint(plan))
	}
}

// The endpoint is a second door into a tunnel, so it has to honour the same guest
// list as the first. Admitting the whole client subnet made it a way around the very
// choice it exists to offer: a device left on `direct`, or excluded from the tunnel
// by allowed_devices, could point one application at the port and leave through it.
func TestSocksAdmitsOnlyThePermittedDevices(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Socks = []domain.SocksEndpoint{{
		TunnelID:  "corp",
		Address:   "10.90.0.1",
		Interface: "vh-corp",
		Port:      11080,
		Clients:   []string{"10.80.0.2"},
	}}
	ruleset := RenderRuleset(plan)

	if !strings.Contains(ruleset, "elements = { 10.80.0.2 }") {
		t.Fatalf("the permitted device is not in a set:\n%s", ruleset)
	}
	if strings.Contains(ruleset, `ip saddr `+plan.ClientCIDR+` oifname "vh-corp"`) {
		t.Errorf("the endpoint still admits the whole client subnet:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, `ip saddr @allowed_corp oifname "vh-corp" tcp dport 11080 accept`) {
		t.Errorf("the endpoint does not match the permitted set:\n%s", ruleset)
	}
}

// An empty set is the right rendering of "nobody is allowed": nftables matches
// nothing against it, so the rule exists and admits no one. Omitting the set would
// make the rule fail to load and take the whole ruleset down with it.
func TestATunnelNobodyMayUseRendersAnEmptySet(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Socks = []domain.SocksEndpoint{
		{TunnelID: "corp", Address: "10.90.0.1", Interface: "vh-corp", Port: 11080},
	}
	ruleset := RenderRuleset(plan)

	if !strings.Contains(ruleset, "set allowed_corp {") {
		t.Fatalf("the set is missing, so the rule referencing it cannot load:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "elements = { }") {
		t.Errorf("an empty elements line is not valid nftables syntax:\n%s", ruleset)
	}
}

// A private network carried by sing-box or OpenVPN needs the same two rules an
// egress does, because the process reaching the provider runs inside the namespace
// either way. Without them the tunnel never connects at all -- and the ruleset looks
// perfectly correct while it fails.
func TestAProxiedPrivateNetworkCanReachItsProvider(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.LinkBase = "10.90.0.0/16"
	plan.Internals = []domain.InternalNetwork{{
		TunnelID:  "corp",
		Mark:      0x102,
		Interface: "vh-corp",
		Routes:    []string{"10.20.0.0/16"},
		Proxied:   true,
	}}
	ruleset := RenderRuleset(plan)

	// Its own connections out to the provider are forwarded, not originated here.
	if !strings.Contains(ruleset, `iifname "vh-corp" oifname "eth0" accept`) {
		t.Errorf("the namespace cannot reach the provider:\n%s", ruleset)
	}
	// And they leave translated, since the internet cannot answer a link address.
	if !strings.Contains(ruleset, `ip saddr 10.90.0.0/16 oifname "eth0" masquerade`) {
		t.Errorf("the provider would see an unroutable source address:\n%s", ruleset)
	}
}

// The comment claimed for a long time that DoT was refused outright while no rule
// existed. A client with DoT on resolves private names past split-DNS, their
// addresses never enter the set, and the traffic that follows leaves through the
// internet provider.
func TestDNSOverTLSIsRefused(t *testing.T) {
	t.Parallel()
	ruleset := RenderRuleset(directOnlyPlan())

	rule := `iifname "awg0" tcp dport 853 reject with tcp reset`
	if !strings.Contains(ruleset, rule) {
		t.Fatalf("DoT is not refused:\n%s", ruleset)
	}
	// Before any rule that would accept it: order decides which one matches.
	forward := ruleset[strings.Index(ruleset, "chain forward"):strings.Index(ruleset, "chain input")]
	if strings.Index(forward, rule) > strings.Index(forward, "accept\n\t\tiifname") && strings.Contains(forward, "oifname \"eth0\" accept") {
		if strings.Index(forward, rule) > strings.Index(forward, "oifname \"eth0\" accept") {
			t.Errorf("an egress rule accepts DoT before it is refused:\n%s", forward)
		}
	}
}

// A hub that cannot read its own ruleset must not report that the ruleset is gone.
// Both answers used to be the empty string, so a permission error or a missing nft
// binary read as "someone flushed the table" and the agent set about rebuilding
// something that may have been perfectly correct.
func TestAFailedReadIsNotAnAbsentTable(t *testing.T) {
	t.Parallel()

	// The message nft actually prints for a table that is not there, checked
	// against nft 1.0.9 on the host.
	absent := &fakeHost{failures: map[string]error{
		"nft -j list table inet vpn_hub": errors.New(
			"nft -j list table inet vpn_hub: exit status 1: Error: No such file or directory"),
	}}
	fingerprint, err := (NFTables{Run: absent.run}).Observe(context.Background())
	if err != nil {
		t.Fatalf("a missing table should not be an error: %v", err)
	}
	if fingerprint != "" {
		t.Errorf("fingerprint = %q, want empty for an absent table", fingerprint)
	}

	refused := &fakeHost{failures: map[string]error{
		"nft -j list table inet vpn_hub": errors.New(
			"nft -j list table inet vpn_hub: exit status 1: Error: Could not open: Permission denied"),
	}}
	if _, err := (NFTables{Run: refused.run}).Observe(context.Background()); err == nil {
		t.Error("a failed read was reported as an absent table")
	}
}
