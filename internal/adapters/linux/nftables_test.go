package linux

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
		DNSDestinations: []domain.DNSDestination{{
			ClientAddresses: []string{"10.80.0.2", "10.80.0.3"}, ResolverAddress: "10.80.0.1",
		}},
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
	plan.Egresses[0].Addresses = []string{"10.80.0.2", "10.80.0.3"}
	plan.DNSDestinations = []domain.DNSDestination{
		{ClientAddresses: []string{"10.80.0.2", "10.80.0.3"}, ResolverAddress: "10.80.0.1"},
		{ClientAddresses: []string{"10.80.0.4"}, ResolverAddress: "10.90.0.1"},
	}
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

func TestDNSQueriesDNATToEachDevicesResolver(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Egresses[0].Addresses = []string{"10.80.0.2"}
	plan.Egresses = append(plan.Egresses, domain.EgressGroup{
		ID: "wg-nl", Mark: 0x101, Interface: "vh-wg-nl", Addresses: []string{"10.80.0.3"},
	})
	plan.DNSDestinations = []domain.DNSDestination{
		{ClientAddresses: []string{"10.80.0.2"}, ResolverAddress: "10.80.0.1"},
		{ClientAddresses: []string{"10.80.0.3"}, ResolverAddress: "10.90.0.1"},
	}

	rendered := RenderRuleset(plan)
	for _, wanted := range []string{
		"set dns_clients_direct {",
		"set dns_clients_wg_nl {",
		"set dns_clients_admitted {",
		`iifname "awg0" ip saddr @dns_clients_direct udp dport 53 dnat ip to 10.80.0.1:53`,
		`iifname "awg0" ip saddr @dns_clients_direct tcp dport 53 dnat ip to 10.80.0.1:53`,
		`iifname "awg0" ip saddr @dns_clients_wg_nl udp dport 53 dnat ip to 10.90.0.1:53`,
		`iifname "awg0" ip saddr @dns_clients_wg_nl tcp dport 53 dnat ip to 10.90.0.1:53`,
		`iifname "awg0" ip saddr @dns_clients_wg_nl ip daddr 10.90.0.1 udp dport 53 accept`,
		`iifname "awg0" ip saddr @dns_clients_wg_nl ip daddr 10.90.0.1 tcp dport 53 accept`,
		`iifname "awg0" ip saddr @dns_clients_wg_nl udp dport 53 drop`,
	} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q:\n%s", wanted, rendered)
		}
	}
	chain := rendered[strings.Index(rendered, "chain prerouting_nat {"):]
	catchAll := `iifname "awg0" ip saddr @dns_clients_admitted udp dport 53 dnat ip to 10.80.0.1:53`
	if !strings.Contains(chain, catchAll) {
		t.Fatalf("the admitted-client fallback is missing:\n%s", chain)
	}
	if strings.Index(chain, catchAll) < strings.Index(chain, "@dns_clients_wg_nl") {
		t.Errorf("the catch-all shadows source-aware DNS routing:\n%s", chain)
	}
}

func TestDNSFallbackRemainsLimitedToAdmittedClientsWithoutDestinations(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.DNSDestinations = nil

	rendered := RenderRuleset(plan)
	for _, wanted := range []string{
		"set dns_clients_admitted {",
		`iifname "awg0" ip saddr @dns_clients_admitted ip daddr 10.80.0.1 udp dport 53 accept`,
		`iifname "awg0" ip saddr @dns_clients_admitted udp dport 53 dnat ip to 10.80.0.1:53`,
	} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing admitted-client DNS guard %q:\n%s", wanted, rendered)
		}
	}
	if strings.Contains(rendered, `iifname "awg0" udp dport 53 dnat`) {
		t.Errorf("DNS fallback is reachable without an admitted source:\n%s", rendered)
	}
	input := rendered[strings.Index(rendered, "chain input {"):strings.Index(rendered, "chain output")]
	drop := `iifname "awg0" udp dport 53 drop`
	if !strings.Contains(input, drop) || strings.Index(input, drop) > strings.Index(input, "ct state established,related accept") {
		t.Errorf("stale DNS conntrack is not denied before established traffic:\n%s", input)
	}
}

func TestRevokedClientCannotUseDNSWhenIngressRemovalFails(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Egresses = nil
	plan.DNSDestinations = []domain.DNSDestination{{ResolverAddress: "10.90.0.1"}}

	rendered := RenderRuleset(plan)
	input := rendered[strings.Index(rendered, "chain input {"):strings.Index(rendered, "chain output")]
	nat := rendered[strings.Index(rendered, "chain prerouting_nat {"):]
	if strings.Contains(input, "dport 53 accept") || strings.Contains(nat, "dport 53 dnat") {
		t.Fatalf("a stale ingress peer retains DNS access after revocation:\n%s", rendered)
	}
	if !strings.Contains(input, `iifname "awg0" udp dport 53 drop`) {
		t.Fatalf("revoked DNS conntrack is not explicitly denied:\n%s", rendered)
	}
}

func TestDNSConntrackIsClearedForChangedAndRevokedClients(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	host := &fakeHost{replies: map[string]string{
		"nft -j list table inet vpn_hub": `{"nftables":[{"table":{"comment":"vpn-hub:old"}}]}`,
	}}
	adapter := NFTables{Run: host.run, RuntimeDir: directory}
	previous := directOnlyPlan()
	previous.Egresses[0].Addresses = append(previous.Egresses[0].Addresses, "10.80.0.4")
	previous.DNSDestinations[0].ClientAddresses = append(previous.DNSDestinations[0].ClientAddresses, "10.80.0.4")
	if _, err := adapter.Apply(context.Background(), previous); err != nil {
		t.Fatalf("seed previous plan: %v", err)
	}
	host.commands = nil

	next := directOnlyPlan()
	next.Egresses = []domain.EgressGroup{
		{ID: domain.EgressDirect, Mark: 0x100, Interface: "eth0", Addresses: []string{"10.80.0.4"}},
		{ID: "wg-nl", Mark: 0x101, Interface: "vh-wg-nl", Addresses: []string{"10.80.0.2"}},
	}
	next.DNSDestinations = []domain.DNSDestination{{
		ClientAddresses: []string{"10.80.0.2"}, ResolverAddress: "10.90.0.1",
	}}
	if _, err := adapter.Apply(context.Background(), next); err != nil {
		t.Fatalf("apply changed plan: %v", err)
	}

	want := []string{
		"conntrack -D -p udp -s 10.80.0.2 --dport 53",
		"conntrack -D -p tcp -s 10.80.0.2 --dport 53",
		"conntrack -D -p udp -s 10.80.0.3 --dport 53",
		"conntrack -D -p tcp -s 10.80.0.3 --dport 53",
	}
	var got []string
	for _, command := range host.commands {
		if strings.HasPrefix(command, "conntrack ") {
			got = append(got, command)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("conntrack cleanup = %v, want %v", got, want)
	}
}

func TestDNSConntrackCleanupFailureIsRetriedAndNeverReportedAsApplied(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	host := &fakeHost{replies: map[string]string{
		"nft -j list table inet vpn_hub": `{"nftables":[{"table":{"comment":"vpn-hub:old"}}]}`,
	}}
	adapter := NFTables{Run: host.run, RuntimeDir: directory}
	previous := directOnlyPlan()
	if _, err := adapter.Apply(context.Background(), previous); err != nil {
		t.Fatalf("seed previous plan: %v", err)
	}

	next := directOnlyPlan()
	next.DNSDestinations[0].ResolverAddress = "10.90.0.1"
	failing := "conntrack -D -p udp -s 10.80.0.2 --dport 53"
	host.failures = map[string]error{failing: errors.New("operation not permitted")}
	rebuilt, err := adapter.Apply(context.Background(), next)
	const wantError = "clear udp DNS conntrack for 10.80.0.2: operation not permitted"
	if err == nil || err.Error() != wantError {
		t.Fatalf("Apply error = %v, want %q", err, wantError)
	}
	if rebuilt {
		t.Fatal("Apply reported success before required DNS conntrack cleanup")
	}

	host.failures = nil
	host.commands = nil
	host.replies["nft -j list table inet vpn_hub"] = fmt.Sprintf(
		`{"nftables":[{"table":{"comment":"vpn-hub:%s"}}]}`, Fingerprint(next))
	if rebuilt, err := adapter.Apply(context.Background(), next); err != nil || rebuilt {
		t.Fatalf("retry = (%t, %v), want cleanup without another rebuild", rebuilt, err)
	}
	if !host.ran(failing) {
		t.Fatalf("failed cleanup was not retried; commands: %v", host.commands)
	}
}

func TestRenderIngressFallback(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.DNSDestinations = nil
	plan.AltUDP443 = true
	plan.RealityPort = domain.RealityPort
	// A tunnel egress as well as direct: the fallback listener opens hub-originated
	// connections into it on a device's behalf, which is what the extra masquerade
	// in the golden file exists for.
	plan.Egresses = append(plan.Egresses, domain.EgressGroup{
		ID:        "provider-nl",
		Mark:      0x101,
		Interface: "vh-provider-nl",
		Addresses: []string{"10.80.0.4"},
	})
	goldenTest(t, "ingress-fallback", plan)
}

// The hub's own address is public, so refusing private destinations in the
// listener does not cover it -- and the local table resolves it over loopback,
// which the input chain otherwise accepts. Without this an authenticated device
// could reach SSH on the hub without crossing the cloud firewall that decides who
// may.
func TestLocalServicesAreClosedToMarkedTraffic(t *testing.T) {
	t.Parallel()
	rendered := RenderRuleset(directOnlyPlan())

	chain := rendered[strings.Index(rendered, "chain input {"):]
	chain = chain[:strings.Index(chain, "\t}")]

	drop := `iif lo meta mark != 0x00000000 drop`
	if !strings.Contains(chain, drop) {
		t.Fatalf("marked traffic may still reach the hub's own services:\n%s", chain)
	}
	// Ahead of the blanket loopback accept, or it guards nothing.
	if strings.Index(chain, drop) > strings.Index(chain, "iif lo accept") {
		t.Errorf("the drop comes after the accept it is meant to precede:\n%s", chain)
	}
	// The resolver is the one local service this path legitimately needs.
	for _, protocol := range []string{"udp", "tcp"} {
		exception := fmt.Sprintf(`iif lo meta mark != 0x00000000 ip daddr 10.80.0.1 %s dport 53 accept`, protocol)
		if !strings.Contains(chain, exception) {
			t.Errorf("the listener cannot resolve names over %s:\n%s", protocol, chain)
		}
		if strings.Index(chain, exception) > strings.Index(chain, drop) {
			t.Errorf("the %s resolver exception comes after the drop:\n%s", protocol, chain)
		}
	}
}

// output_mark marks by destination alone -- it cannot see who asked -- so it must
// not touch a socket that already chose its way out. The fallback listener's
// connections carry the mark of their device's egress; re-marking them into a
// private network's tunnel would hand a device access that allowed_devices denies
// it, because that list is enforced in the forward chain and this traffic never
// reaches it. Refusing private addresses in the listener is not enough on its own:
// a private network may route a public prefix, and split DNS adds whatever its
// zones resolve to.
func TestOutputMarkLeavesAlreadyMarkedTrafficAlone(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Internals = []domain.InternalNetwork{{
		TunnelID: "corp", Mark: 0x102, Interface: "vh-corp", Routes: []string{"10.20.0.0/16"},
	}}
	rendered := RenderRuleset(plan)

	chain := rendered[strings.Index(rendered, "chain output_mark {"):]
	chain = chain[:strings.Index(chain, "\t}")]
	guard := "meta mark != 0x00000000 return"
	if !strings.Contains(chain, guard) {
		t.Fatalf("output_mark does not spare already-marked traffic:\n%s", chain)
	}
	// Ahead of the marking, or it would guard nothing.
	if strings.Index(chain, guard) > strings.Index(chain, "meta mark set") {
		t.Errorf("the guard comes after the marking it is supposed to precede:\n%s", chain)
	}
}

// The kill switch has to cover traffic the hub originates on a client's behalf,
// not only forwarded traffic. `ip rule fwmark N lookup N` fails OPEN -- a table
// with no matching route falls through to main and the packet leaves by the hub's
// own uplink -- so the output chain has to say what the forward chain's drop
// policy says for everyone else.
func TestOutputChainDropsMarkedTrafficLeavingTheWrongWay(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Egresses = append(plan.Egresses, domain.EgressGroup{
		ID: "provider-nl", Mark: 0x101, Interface: "vh-provider-nl",
	})
	plan.Internals = []domain.InternalNetwork{{
		TunnelID: "corp", Mark: 0x102, Interface: "vh-corp", Routes: []string{"10.20.0.0/16"},
	}}
	rendered := RenderRuleset(plan)

	for _, rule := range []string{
		`meta mark 0x00000101 oifname != "vh-provider-nl" drop`,
		`meta mark 0x00000102 oifname != "vh-corp" drop`,
	} {
		if !strings.Contains(rendered, rule) {
			t.Errorf("missing %q:\n%s", rule, rendered)
		}
	}
	// direct is the uplink, which is where an unmarked socket goes anyway.
	if strings.Contains(rendered, `meta mark 0x00000100 oifname !=`) {
		t.Error("the direct egress got a rule that would drop its own traffic")
	}
}

// The fallbacks open a port and rewrite a destination, so their absence has to be
// as exact as their presence: with the gate off nothing may accept on 443, and no
// redirect may exist to catch a client's own QUIC traffic.
func TestFallbackRulesAreAbsentWhenOff(t *testing.T) {
	t.Parallel()
	ruleset := RenderRuleset(directOnlyPlan())
	for _, rule := range []string{"tcp dport 443", "redirect to :"} {
		if strings.Contains(ruleset, rule) {
			t.Errorf("%q is present with the fallback off:\n%s", rule, ruleset)
		}
	}
}

// The redirect must never match traffic arriving from clients: an unscoped rule
// would rewrite a forwarded QUIC or HTTP/3 request to any site's :443 and break it
// in a way that looks like the site's fault.
func TestAltUDP443IsScopedToTheUplink(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.AltUDP443 = true
	ruleset := RenderRuleset(plan)

	// `dnat to :port` rather than `redirect`, which would also rewrite the
	// destination address to the interface's primary one and break every client
	// dialling a secondary or floating address.
	want := `iifname "eth0" meta nfproto ipv4 udp dport 443 dnat to :51820`
	if !strings.Contains(ruleset, want) {
		t.Fatalf("missing %q:\n%s", want, ruleset)
	}
	if strings.Contains(ruleset, "redirect to") {
		t.Errorf("the address-rewriting form came back:\n%s", ruleset)
	}
	if strings.Contains(ruleset, `iifname "awg0" udp dport 443`) {
		t.Errorf("the rule also matches the ingress interface:\n%s", ruleset)
	}
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

// The forwarded-TCP MSS clamp must match on the SYN|RST mask, not a bare `flags syn`.
// A bare match compiles to an equality test on the whole flags byte and so catches
// only a pure SYN (0x02), missing the SYN-ACK (0x12) -- which would clamp only one
// direction and leave half the transfers stalling on a low-MTU path. It must also
// precede the established-state accept so the (new) SYN and SYN-ACK both reach it.
func TestForwardChainClampsMSSBothDirections(t *testing.T) {
	t.Parallel()
	rendered := RenderRuleset(directOnlyPlan())

	clampRule := "tcp flags & (syn|rst) == syn tcp option maxseg size set"
	clamp := strings.Index(rendered, clampRule)
	if clamp < 0 {
		t.Fatalf("MSS clamp must match SYN and SYN-ACK via the syn|rst mask:\n%s", rendered)
	}
	if strings.Contains(rendered, "\t\ttcp flags syn tcp option maxseg") {
		t.Error("bare `flags syn` misses the SYN-ACK; use the syn|rst mask")
	}
	established := strings.Index(rendered, "ct state established,related accept")
	if established < 0 || clamp > established {
		t.Error("the MSS clamp must precede the established-state accept")
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

// A client ACL only works if the packet still reaches the forward chain on the
// ingress interface. The default-egress rule matches on source alone, so without an
// earlier return it marks traffic between two clients as well, and policy routing
// hands it to the egress namespace where the destination does not exist. The ACL
// rules require oifname == ingress and so never match: the hole the operator opened
// stays shut, and the ruleset gives no sign of why.
func TestClientToClientTrafficIsNotMarkedForEgress(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	rendered := RenderRuleset(plan)

	intra := strings.Index(rendered, "ip daddr "+plan.ClientCIDR+" return")
	egress := strings.Index(rendered, "ip saddr @client_direct meta mark")
	if intra < 0 {
		t.Fatalf("traffic within the client CIDR must be left unmarked:\n%s", rendered)
	}
	if egress < 0 {
		t.Fatalf("the default-egress rule must be present:\n%s", rendered)
	}
	if intra > egress {
		t.Error("the intra-VPN return must be evaluated before the default egress")
	}
}

// ...and it must not shadow the private networks while doing it. A route lying
// inside the client subnet is a configuration nothing rejects: routes are checked
// against each other, and the subnet against the egress link base, but the two are
// never checked against one another. Such a destination reached its tunnel by the
// internal mark outranking the directly attached client subnet, so the return added
// for client-to-client traffic has to be matched after the internal sets, not before
// them -- ahead of them it ends the chain first and the packet goes back out the
// ingress interface instead of down the tunnel.
func TestPrivateNetworksOutrankTheIntraVPNReturn(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Internals = []domain.InternalNetwork{{
		TunnelID: "corp-a", Mark: 0x102, Interface: "vh-corp-a",
		// Deliberately inside the client CIDR, which is what nothing rejects.
		Routes: []string{"10.80.0.128/25"},
	}}
	rendered := RenderRuleset(plan)

	internal := strings.Index(rendered, "ip daddr @internal_corp_a")
	intra := strings.Index(rendered, "ip daddr "+plan.ClientCIDR+" return")
	if internal < 0 || intra < 0 {
		t.Fatalf("both rules must be present:\n%s", rendered)
	}
	if internal > intra {
		t.Error("the private-network rule must be evaluated before the intra-VPN return")
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
	plan.DNSDestinations = nil
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

// An egress tunnel nobody has chosen as their default has an empty set, and
// `elements = { }` does not parse -- nft rejects the whole ruleset, so the hub
// applies nothing at all and every client loses its connection. Found on the host,
// not here, which is why this test exists.
func TestAnEgressNobodyDefaultsToRendersNoElementsLine(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.Egresses = append(plan.Egresses, domain.EgressGroup{
		ID:        "nl",
		Mark:      0x101,
		Interface: "vh-nl",
	})
	ruleset := RenderRuleset(plan)

	if strings.Contains(ruleset, "elements = {  }") || strings.Contains(ruleset, "elements = { }") {
		t.Fatalf("an empty elements line is a syntax error, so nft rejects everything:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "set client_nl {") {
		t.Errorf("the set must still exist, since rules refer to it:\n%s", ruleset)
	}
}

func TestClientACLRulesPrecedeClientToClientDrop(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.ClientACLs = []domain.ClientPortACL{{SourceAddress: "10.80.0.2", TargetAddress: "10.80.0.3", Protocol: domain.ClientACLTCP, Port: 22}}
	rendered := RenderRuleset(plan)
	allow := `iifname "awg0" oifname "awg0" ip saddr 10.80.0.2 ip daddr 10.80.0.3 tcp dport 22 accept`
	drop := `iifname "awg0" oifname "awg0" drop`
	if !strings.Contains(rendered, allow) {
		t.Fatalf("missing client ACL rule %q:\n%s", allow, rendered)
	}
	if strings.Index(rendered, allow) > strings.Index(rendered, drop) {
		t.Fatalf("client ACL is after the blanket drop:\n%s", rendered)
	}
}

func TestClientACLAnySourceUsesClientCIDR(t *testing.T) {
	t.Parallel()
	plan := directOnlyPlan()
	plan.ClientACLs = []domain.ClientPortACL{{TargetAddress: "10.80.0.3", Protocol: domain.ClientACLUDP, Port: 5353}}
	rendered := RenderRuleset(plan)
	want := `iifname "awg0" oifname "awg0" ip saddr 10.80.0.0/24 ip daddr 10.80.0.3 udp dport 5353 accept`
	if !strings.Contains(rendered, want) {
		t.Fatalf("missing any-source client ACL rule %q:\n%s", want, rendered)
	}
}
