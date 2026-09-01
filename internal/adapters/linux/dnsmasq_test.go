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

// listResolverUnits is the command the stale sweep enumerates with.
const listResolverUnits = "systemctl list-units --all --plain --no-legend " +
	resolverUnitPrefix + "*.service"

// The whole point of the forwarder is where it asks from: a private DNS server is
// reachable from inside the tunnel and from nowhere else.
func TestPrivateResolverRunsInsideItsOwnNamespace(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	dns := Dnsmasq{Run: host.run, ConfigDir: t.TempDir()}

	if err := dns.Apply(context.Background(), privateDNSPlan(), false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("--unit=vpn-hub-dns-private-corp-a --property=Restart=on-failure ip netns exec vpn-hub-corp-a dnsmasq") {
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
		listResolverUnits: "  vpn-hub-dns-private-corp-a.service loaded active running dnsmasq\n" +
			"\u25cf vpn-hub-dns-private-gone.service loaded failed failed dnsmasq\n",
	}}
	stale := filepath.Join(directory, privateResolverConfig("gone"))
	if err := os.WriteFile(stale, []byte("listen-address=10.90.0.6\n"), 0o600); err != nil {
		t.Fatalf("seed a stale configuration: %v", err)
	}

	dns := Dnsmasq{Run: host.run, ConfigDir: directory}
	if err := dns.Apply(context.Background(), privateDNSPlan(), false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !host.ran("systemctl stop vpn-hub-dns-private-gone.service") {
		t.Errorf("the withdrawn network kept its resolver; commands: %v", host.commands)
	}
	if host.ran("--unit=vpn-hub-dns-private-gone ") {
		t.Errorf("the withdrawn network's resolver was restarted rather than reaped; commands: %v", host.commands)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the withdrawn network's configuration outlived it: %v", err)
	}
	// The network still in the revision keeps its forwarder.
	if !host.ran("--unit=vpn-hub-dns-private-corp-a ") {
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
		listResolverUnits: errors.New("Failed to connect to bus"),
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
		listResolverUnits: "  vpn-hub-dns-corp-a.service loaded active running dnsmasq\n",
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
		if started < 0 && strings.Contains(command, "--unit=vpn-hub-dns-private-corp-a ") {
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
		listResolverUnits: "  " + upstreamResolverUnit + ".service loaded active running dnsmasq\n",
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

// A hub upgraded from the build where the names collided carries a unit called
// vpn-hub-dns-upstream, and for a tunnel with that id there is no telling which
// resolver is behind it: the private forwarder claimed the name first, and the public
// one, finding it already active and its own configuration unchanged, left it alone.
//
// Exempting that name would keep the private process running. Its replacement could
// not bind the address, and the public resolver -- unchanged and apparently active --
// would never be replaced, so public queries would go on reaching the corporate
// resolver. This reproduces that host: only the collided unit is running, and both
// configurations are already on disk exactly as they render.
func TestTheCollidedNameFromThePreviousBuildIsNotExempted(t *testing.T) {
	t.Parallel()
	plan := privateDNSPlan()
	plan.PrivateResolvers[0].TunnelID = "upstream"
	plan.PrivateResolvers[0].Namespace = "vpn-hub-upstream"

	directory := t.TempDir()
	for name, content := range map[string]string{
		privateResolverConfig("upstream"): RenderPrivateResolver(plan.PrivateResolvers[0]),
		"dnsmasq-upstream.conf":           RenderUpstreamResolver(plan),
		"dnsmasq-hub.conf":                RenderHubResolver(plan),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	const collided = "vpn-hub-dns-upstream"
	host := &fakeHost{
		replies: map[string]string{
			listResolverUnits: "  " + collided + ".service loaded active running dnsmasq\n",
		},
		// What is running is a fact about the host, so it is spelled out literally
		// rather than through the constants under test. On that host the collided
		// unit and the hub's own resolver are up, and nothing else is -- which is
		// precisely what lets an unchanged public configuration be skipped.
		failures: map[string]error{
			"systemctl is-active --quiet vpn-hub-dns-public.service":           errors.New("inactive"),
			"systemctl is-active --quiet vpn-hub-dns-private-upstream.service": errors.New("inactive"),
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
		case private < 0 && strings.Contains(command, "--unit="+privateResolverUnit("upstream")+" "):
			private = index
		case public < 0 && strings.Contains(command, "--unit="+upstreamResolverUnit+" "):
			public = index
		}
	}
	if reaped < 0 {
		t.Fatalf("the collided unit was exempted, so the old forwarder kept the address and the name; commands: %v",
			host.commands)
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
	// The public forwarder must reach the public namespace, not the corporate one.
	if !host.ran("--unit=" + upstreamResolverUnit + " --property=Restart=on-failure ip netns exec vpn-hub-provider-nl") {
		t.Errorf("public queries were not sent to the public namespace; commands: %v", host.commands)
	}
}
