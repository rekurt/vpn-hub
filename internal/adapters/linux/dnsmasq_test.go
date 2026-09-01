package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func dnsPlan() domain.DNSPlan {
	return domain.DNSPlan{
		ListenAddress: "10.80.0.1",
		ClientCIDR:    "10.80.0.0/24",
		Zones: []domain.DNSZoneRoute{{
			Zone: "corp.internal", Resolvers: []string{"10.20.0.53"}, Set: "internal_corp_a",
		}},
		UpstreamNamespace: "vpn-hub-provider-nl",
		UpstreamAddress:   "10.90.0.2",
		PublicResolvers:   []string{"1.1.1.1"},
	}
}

// The nftset directive is what makes a private name usable: without it the address
// resolves and then routes out of the internet path.
func TestPrivateZonesAreSentToTheirResolverAndSet(t *testing.T) {
	t.Parallel()
	rendered := RenderHubResolver(dnsPlan())
	for _, wanted := range []string{
		"server=/corp.internal/10.20.0.53",
		"nftset=/corp.internal/inet#vpn_hub#internal_corp_a",
	} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q:\n%s", wanted, rendered)
		}
	}
}

// Public queries go to the resolver inside the egress namespace, never straight out
// of the hub, or the provider carries the traffic while DNS still names the hub.
func TestPublicQueriesGoToTheNamespaceResolver(t *testing.T) {
	t.Parallel()
	rendered := RenderHubResolver(dnsPlan())
	if !strings.Contains(rendered, "server=10.90.0.2") {
		t.Errorf("expected forwarding to the namespace resolver:\n%s", rendered)
	}
	if strings.Contains(rendered, "server=1.1.1.1") {
		t.Errorf("the hub resolver must not query public servers directly:\n%s", rendered)
	}
}

func TestWithoutANamespaceTheHubQueriesPublicServers(t *testing.T) {
	t.Parallel()
	plan := dnsPlan()
	plan.UpstreamNamespace = ""
	plan.UpstreamAddress = ""

	rendered := RenderHubResolver(plan)
	if !strings.Contains(rendered, "server=1.1.1.1") {
		t.Errorf("expected direct public resolvers:\n%s", rendered)
	}
}

func TestUpstreamResolverOnlyForwards(t *testing.T) {
	t.Parallel()
	rendered := RenderUpstreamResolver(dnsPlan())
	if !strings.Contains(rendered, "listen-address=10.90.0.2") {
		t.Errorf("expected it to listen inside the namespace:\n%s", rendered)
	}
	if strings.Contains(rendered, "nftset=") {
		t.Error("only the hub resolver populates sets")
	}
}

// The resolver answers clients, not the internet.
func TestResolverIsNotOpenToTheWorld(t *testing.T) {
	t.Parallel()
	rendered := RenderHubResolver(dnsPlan())
	for _, wanted := range []string{"bind-interfaces", "local-service", "listen-address=10.80.0.1"} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q:\n%s", wanted, rendered)
		}
	}
}

// privateDNSPlan adds a network that resolves through its own tunnel, which is the
// arrangement the per-network forwarders exist for.
func privateDNSPlan() domain.DNSPlan {
	plan := dnsPlan()
	plan.Zones[0].ForwardAddress = "10.90.0.2"
	plan.PrivateResolvers = []domain.DNSPrivateResolver{{
		TunnelID:  "corp-a",
		Namespace: "vpn-hub-corp-a",
		Address:   "10.90.0.2",
		Resolvers: []string{"10.20.0.53"},
	}}
	return plan
}

// The stale sweep enumerates two spaces: the one this build generates into, and the
// one the older build did.
const (
	listCurrentUnits = "systemctl list-units --all --plain --no-legend " +
		resolverUnitPrefix + "*.service"
	listLegacyUnits = "systemctl list-units --all --plain --no-legend " +
		legacyResolverPrefix + "*.service"
)

// The whole point of the forwarder is where it asks from: a private DNS server is
// reachable from inside the tunnel and from nowhere else.
func TestPrivateResolverRunsInsideItsOwnNamespace(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	dns := Dnsmasq{Run: host.run, ConfigDir: t.TempDir()}

	if err := dns.Apply(context.Background(), privateDNSPlan(), false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("--unit=" + privateResolverUnit("corp-a") + " --property=Restart=on-failure ip netns exec vpn-hub-corp-a dnsmasq") {
		t.Fatalf("the forwarder did not start inside its namespace; commands: %v", host.commands)
	}
}

// Only "direct" is a reserved tunnel id, so a network may legitimately be called
// "upstream". Named without the "private-" segment its forwarder would claim the unit
// the public resolver already uses, and the two would evict each other from it on
// every reconcile -- leaving whichever started last answering for both.
func TestAPrivateResolverCannotEvictTheUpstreamOne(t *testing.T) {
	t.Parallel()
	plan := privateDNSPlan()
	plan.PrivateResolvers[0].TunnelID = "upstream"
	plan.PrivateResolvers[0].Namespace = "vpn-hub-upstream"

	host := &fakeHost{}
	dns := Dnsmasq{Run: host.run, ConfigDir: t.TempDir()}
	if err := dns.Apply(context.Background(), plan, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// One pass starts three resolvers -- this network's forwarder, the public one and
	// the hub's -- and each needs a transient unit of its own. Asserting that both
	// commands ran would prove nothing: under a shared name both do run, and the
	// second simply replaces the first. A name claimed twice is the defect itself.
	started := map[string]string{}
	for _, command := range host.commands {
		if !strings.HasPrefix(command, "systemd-run ") {
			continue
		}
		for _, field := range strings.Fields(command) {
			unit, isUnit := strings.CutPrefix(field, "--unit=")
			if !isUnit {
				continue
			}
			if previous, taken := started[unit]; taken {
				t.Fatalf("two resolvers claimed the unit %q, so the second evicted the first:\n  %s\n  %s",
					unit, previous, command)
			}
			started[unit] = command
		}
	}
	if len(started) != 3 {
		t.Errorf("expected this network's, the public and the hub's resolvers to start, got %d: %v",
			len(started), host.commands)
	}
}

// A tunnel that merely drops its dns_zones keeps its namespace, so the egress adapter
// never visits it. Without this sweep its forwarder would hold the namespace's veth
// address for as long as the hub runs, answering from a revision that is gone.
func TestAWithdrawnNetworksResolverIsReaped(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	// The withdrawn unit is printed with the leading bullet systemd gives a failed
	// one, which shifts every column right by one.
	host := &fakeHost{replies: map[string]string{
		listCurrentUnits: "  " + privateResolverUnit("corp-a") + ".service loaded active running dnsmasq\n" +
			"\u25cf " + privateResolverUnit("gone") + ".service loaded failed failed dnsmasq\n",
	}}
	stale := filepath.Join(directory, privateResolverConfig("gone"))
	if err := os.WriteFile(stale, []byte("listen-address=10.90.0.6\n"), 0o600); err != nil {
		t.Fatalf("seed a stale configuration: %v", err)
	}

	dns := Dnsmasq{Run: host.run, ConfigDir: directory}
	if err := dns.Apply(context.Background(), privateDNSPlan(), false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !host.ran("systemctl stop " + privateResolverUnit("gone") + ".service") {
		t.Errorf("the withdrawn network kept its resolver; commands: %v", host.commands)
	}
	if host.ran("--unit=" + privateResolverUnit("gone") + " ") {
		t.Errorf("the withdrawn network's resolver was restarted rather than reaped; commands: %v", host.commands)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the withdrawn network's configuration outlived it: %v", err)
	}
	// The network still in the revision keeps its forwarder.
	if !host.ran("--unit=" + privateResolverUnit("corp-a") + " ") {
		t.Errorf("a network still in the revision lost its resolver; commands: %v", host.commands)
	}
}

// Enumerating is housekeeping. Returning on its failure would leave every client
// without DNS because one bookkeeping command failed -- but swallowing it would let a
// leaked resolver go unreported, since each later pass would conclude afresh that
// there was nothing to reap.
func TestFailingToEnumerateIsReportedWithoutCostingClientsDNS(t *testing.T) {
	t.Parallel()
	host := &fakeHost{failures: map[string]error{
		listCurrentUnits: errors.New("Failed to connect to bus"),
	}}
	dns := Dnsmasq{Run: host.run, ConfigDir: t.TempDir()}

	err := dns.Apply(context.Background(), privateDNSPlan(), false)
	if err == nil {
		t.Fatal("the failure to enumerate was swallowed, so a leaked resolver would never be reported")
	}
	if !host.ran("--unit=" + hubResolverUnit + " --property=") {
		t.Errorf("clients lost their resolver over housekeeping; commands: %v", host.commands)
	}
}

// The forwarders were once named without the "private-" segment. A hub upgraded from
// that build still has one running, holding the very address its replacement is about
// to bind -- and pointing at the same configuration file, so it has to be stopped
// without that file being taken out from under its replacement.
func TestAForwarderFromThePreviousBuildIsReapedButKeepsItsFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	host := &fakeHost{replies: map[string]string{
		listLegacyUnits: "  vpn-hub-dns-corp-a.service loaded active running dnsmasq\n",
	}}

	dns := Dnsmasq{Run: host.run, ConfigDir: directory}
	if err := dns.Apply(context.Background(), privateDNSPlan(), false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	stopped, started := -1, -1
	for index, command := range host.commands {
		if stopped < 0 && strings.Contains(command, "systemctl stop vpn-hub-dns-corp-a.service") {
			stopped = index
		}
		if started < 0 && strings.Contains(command, "--unit="+privateResolverUnit("corp-a")+" ") {
			started = index
		}
	}
	if stopped < 0 {
		t.Fatalf("the previous build's forwarder kept the address; commands: %v", host.commands)
	}
	if started < 0 {
		t.Fatalf("the replacement never started; commands: %v", host.commands)
	}
	if stopped > started {
		t.Errorf("the replacement was started before the address was free: stopped at %d, started at %d",
			stopped, started)
	}
	if _, err := os.Stat(filepath.Join(directory, privateResolverConfig("corp-a"))); err != nil {
		t.Errorf("the running forwarder lost its configuration: %v", err)
	}
}

// The public forwarder has an owner already. Sweeping it as well would stop it in the
// same pass that started it, in the arrangement where it is wanted.
func TestTheSweepLeavesThePublicForwarderAlone(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{
		listCurrentUnits: "  " + upstreamResolverUnit + ".service loaded active running dnsmasq\n",
	}}
	dns := Dnsmasq{Run: host.run, ConfigDir: t.TempDir()}

	if err := dns.Apply(context.Background(), privateDNSPlan(), false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// It is replaced, not reaped: the stop belongs to the restart that follows it.
	for index, command := range host.commands {
		if command != "systemctl stop "+upstreamResolverUnit+".service" {
			continue
		}
		if index+1 >= len(host.commands) ||
			!strings.Contains(host.commands[index+1], "--unit="+upstreamResolverUnit+" ") {
			t.Fatalf("the public forwarder was stopped and not restarted; commands: %v", host.commands)
		}
	}
}

// The older build named every forwarder "vpn-hub-dns-" + tunnel id, so on a host
// upgraded from it a unit in that space says nothing about which resolver it holds:
// for a tunnel whose id happened to match a public forwarder's name, the private one
// claimed the unit first, and the public one -- finding it already active and its own
// configuration unchanged -- left it alone.
//
// Exempting such a name keeps the private process running. Its replacement cannot
// bind the address, and the public resolver, unchanged and apparently active, is
// never replaced, so public queries go on reaching the corporate resolver. Both ids
// below produced exactly that: "upstream" against the original name and "public"
// against the one the first attempt at this fix chose.
func TestNoNameFromTheOlderBuildIsExempted(t *testing.T) {
	t.Parallel()
	for _, tunnelID := range []string{"upstream", "public"} {
		t.Run(tunnelID, func(t *testing.T) {
			t.Parallel()
			plan := privateDNSPlan()
			plan.PrivateResolvers[0].TunnelID = tunnelID
			plan.PrivateResolvers[0].Namespace = "vpn-hub-" + tunnelID

			// Every configuration already on disk exactly as it renders, so nothing
			// is "changed" and Apply may skip a unit it believes is running.
			directory := t.TempDir()
			for name, content := range map[string]string{
				privateResolverConfig(tunnelID): RenderPrivateResolver(plan.PrivateResolvers[0]),
				"dnsmasq-upstream.conf":         RenderUpstreamResolver(plan),
				"dnsmasq-hub.conf":              RenderHubResolver(plan),
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
					t.Fatalf("seed %s: %v", name, err)
				}
			}

			// The name the older build gave this tunnel's forwarder.
			collided := "vpn-hub-dns-" + tunnelID
			host := &fakeHost{
				replies: map[string]string{
					listLegacyUnits: "  " + collided + ".service loaded active running dnsmasq\n",
				},
				// What is running is a fact about the host, so it is spelled out
				// through the names rather than assumed: the collided unit and the
				// hub's own resolver are up, and nothing this build generates is.
				failures: map[string]error{
					"systemctl is-active --quiet " + upstreamResolverUnit + ".service":          errors.New("inactive"),
					"systemctl is-active --quiet " + privateResolverUnit(tunnelID) + ".service": errors.New("inactive"),
				},
			}

			dns := Dnsmasq{Run: host.run, ConfigDir: directory}
			if err := dns.Apply(context.Background(), plan, false); err != nil {
				t.Fatalf("Apply: %v", err)
			}

			reaped, private, public := -1, -1, -1
			for index, command := range host.commands {
				switch {
				case reaped < 0 && command == "systemctl stop "+collided+".service":
					reaped = index
				case private < 0 && strings.Contains(command, "--unit="+privateResolverUnit(tunnelID)+" "):
					private = index
				case public < 0 && strings.Contains(command, "--unit="+upstreamResolverUnit+" "):
					public = index
				}
			}
			if reaped < 0 {
				t.Fatalf("%q was exempted, so the old forwarder kept the address and the name; commands: %v",
					collided, host.commands)
			}
			if private < 0 {
				t.Fatalf("the network's forwarder never started; commands: %v", host.commands)
			}
			if public < 0 {
				t.Fatalf("the public namespace was left without a resolver; commands: %v", host.commands)
			}
			if reaped > private {
				t.Errorf("the replacement was started before the address was free: reaped at %d, started at %d",
					reaped, private)
			}
			// The public forwarder must reach the public namespace, not this one.
			if !host.ran("--unit=" + upstreamResolverUnit + " --property=Restart=on-failure ip netns exec vpn-hub-provider-nl") {
				t.Errorf("public queries were not sent to the public namespace; commands: %v", host.commands)
			}
		})
	}
}

// The guard the two collisions needed. The older build generated "vpn-hub-dns-" plus
// any id the identifier rules allow, so a name this build generates inside that space
// cannot be told apart from a leftover -- and a private name that equals the public
// one is the same fault one level down. Checking the naming functions directly is
// what would have caught both attempts before they shipped.
func TestNoNameThisBuildGeneratesCanBeMistakenForAnother(t *testing.T) {
	t.Parallel()
	// Ids picked for the collisions they caused or reach: "upstream" and "public"
	// each named a public forwarder at some point, and the last two probe the
	// segments that separate the private units.
	for _, tunnelID := range []string{"corp-a", "a", "upstream", "public", "private-abc", "net-abc"} {
		unit := privateResolverUnit(tunnelID)
		if strings.HasPrefix(unit, legacyResolverPrefix) {
			t.Errorf("the forwarder for %q is called %q, inside the space the older build generated into",
				tunnelID, unit)
		}
		if unit == upstreamResolverUnit {
			t.Errorf("the forwarder for %q claims the public unit %q", tunnelID, unit)
		}
	}
	if strings.HasPrefix(upstreamResolverUnit, legacyResolverPrefix) {
		t.Errorf("the public unit %q is inside the space the older build generated into", upstreamResolverUnit)
	}
}
