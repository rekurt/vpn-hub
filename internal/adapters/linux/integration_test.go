//go:build integration

// These tests create real network namespaces, veth pairs, WireGuard interfaces and
// nftables rulesets, so they need root and a Linux kernel and sit behind a build tag.
//
// Run them on a disposable machine -- a CI runner -- and not on a hub you reach over
// SSH. They take ownership of `inet vpn_hub`, which is the same table that keeps the
// management port open, and a test interrupted between flushing and reapplying it
// leaves the host reachable only through the provider's console. That is not a
// hypothetical: it happened, and cost a power cycle.
//
// They drive the production path: the same plan builder, ingress adapter and firewall
// adapter the agent uses. They deliberately use plain WireGuard rather than
// AmneziaWG -- the obfuscation parameters aside the protocol is identical, and the
// AmneziaWG module is built by DKMS, which an ephemeral CI runner cannot do. What is
// under test is the hub's own machinery: ruleset, NAT, peer synchronisation and the
// kill switch, none of which depends on the obfuscation.
package linux_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

const (
	hubInterface  = "wgtest0"
	clientNS      = "vpnhubtest"
	hubVeth       = "vhtest"
	clientVeth    = "vctest"
	clientLink    = "cwgtest0"
	clientHost    = "10.80.0.2"
	clientAddress = clientHost + "/32"
	listenPort    = 51821
)

func sh(t *testing.T, format string, args ...any) string {
	t.Helper()
	command := fmt.Sprintf(format, args...)
	output, err := exec.Command("bash", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("%s\n%s\n%v", command, output, err)
	}
	return strings.TrimSpace(string(output))
}

func try(format string, args ...any) {
	_ = exec.Command("bash", "-c", fmt.Sprintf(format, args...)).Run()
}

// bed is a running hub with one client in its own namespace.
type bed struct {
	apply func(t *testing.T)
	probe func() string
	// applyWith reloads the ruleset after letting a test adjust the plan, which is
	// how a scenario adds something the base configuration has no reason to carry --
	// a SOCKS endpoint, say.
	applyWith func(t *testing.T, adjust func(*domain.FirewallPlan))
	uplink    string
	secrets   string
	// clientHost is the address the ruleset admits, so a scenario can test both
	// sides of an access rule.
	clientHost string
}

// waitForTraffic polls until the tunnel carries traffic, since the first handshake
// takes a moment.
func (b bed) waitForTraffic(t *testing.T) string {
	t.Helper()
	for range 10 {
		if result := b.probe(); result != "BLOCKED" {
			return result
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no traffic reached the internet\n%s", diagnose(t))
	return ""
}

// diagnose collects the state that distinguishes the ways this can fail: no
// handshake, no route, a rule that never matched, or an environment that cannot reach
// the probe target at all.
func diagnose(t *testing.T) string {
	t.Helper()
	var report strings.Builder
	for _, step := range []struct{ title, command string }{
		{"hub interface", fmt.Sprintf("wg show %s", hubInterface)},
		{"client interface", fmt.Sprintf("ip netns exec %s wg show %s", clientNS, clientLink)},
		{"client routes", fmt.Sprintf("ip -n %s route", clientNS)},
		{"client reaches the hub", fmt.Sprintf("ip netns exec %s ping -c2 -W2 10.99.0.1", clientNS)},
		{"client reaches the target", fmt.Sprintf("ip netns exec %s ping -c2 -W2 1.1.1.1", clientNS)},
		{"root namespace reaches the target", "curl -s --max-time 5 -o /dev/null -w '%{http_code}' https://1.1.1.1/cdn-cgi/trace"},
		{"ruleset", "nft list table inet vpn_hub"},
	} {
		output, _ := exec.Command("bash", "-c", step.command+" 2>&1").CombinedOutput()
		fmt.Fprintf(&report, "\n--- %s ---\n%s", step.title, output)
	}
	return report.String()
}

func newBed(t *testing.T) bed {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests configure real interfaces and need root")
	}
	for _, binary := range []string{"ip", "nft", "wg", "jq", "curl", "conntrack"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}

	cleanup := func() {
		try("ip netns del %s", clientNS)
		try("ip link del %s", hubVeth)
		try("ip link del %s", hubInterface)
		try("nft delete table inet vpn_hub")
	}
	cleanup()
	t.Cleanup(cleanup)

	uplink := sh(t, "ip -j route show default | jq -r '.[0].dev'")
	if uplink == "" || uplink == "null" {
		t.Skip("no default route on this machine")
	}
	// If the machine itself cannot reach the probe target, a failure downstream would
	// say nothing about the hub.
	if err := exec.Command("bash", "-c",
		"curl -s --max-time 8 -o /dev/null https://1.1.1.1/cdn-cgi/trace").Run(); err != nil {
		t.Skip("this machine cannot reach the probe target, so the tunnel cannot be judged")
	}

	hubKey := sh(t, "wg genkey")
	hubPublic := sh(t, "echo %q | wg pubkey", hubKey)
	clientKey := sh(t, "wg genkey")
	clientPublic := sh(t, "echo %q | wg pubkey", clientKey)

	state := domain.DesiredState{
		Revision: "integration",
		Hub: domain.Hub{
			Endpoint:        fmt.Sprintf("127.0.0.1:%d", listenPort),
			ServerPublicKey: hubPublic,
			ClientCIDR:      "10.80.0.0/24",
			DNSAddress:      "10.80.0.1",
		},
		Devices: []domain.DeployedDevice{{
			ID: "laptop", Address: clientAddress,
			PublicKey: clientPublic, Egress: domain.EgressDirect,
		}},
	}

	secrets := t.TempDir()
	applyWith := func(t *testing.T, adjust func(*domain.FirewallPlan)) {
		t.Helper()
		plan, err := application.BuildFirewallPlan(state, uplink)
		if err != nil {
			t.Fatalf("BuildFirewallPlan: %v", err)
		}
		spec, err := application.BuildIngressSpec(state, hubKey)
		if err != nil {
			t.Fatalf("BuildIngressSpec: %v", err)
		}
		// Both artefacts are plain structs, so the test renames the interface before
		// anything is applied rather than rewriting rules afterwards. This keeps the
		// test from colliding with a real awg0 on the machine.
		plan.IngressInterface = hubInterface
		plan.ListenPort = listenPort
		spec.Interface = hubInterface
		spec.ListenPort = listenPort
		spec.Parameters = nil // plain WireGuard has no obfuscation knobs
		if adjust != nil {
			adjust(&plan)
		}

		if _, err := (linux.NFTables{RuntimeDir: secrets}).Apply(context.Background(), plan); err != nil {
			t.Fatalf("apply ruleset: %v", err)
		}
		ingress := linux.Ingress{SecretsDir: secrets, LinkType: "wireguard", Tool: "wg"}
		if err := ingress.Apply(context.Background(), spec); err != nil {
			t.Fatalf("apply ingress: %v", err)
		}
	}
	apply := func(t *testing.T) { t.Helper(); applyWith(t, nil) }
	apply(t)

	// The client lives in its own namespace and reaches the hub over a veth pair, so
	// the whole path is exercised without a second machine.
	sh(t, "ip netns add %s", clientNS)
	sh(t, "ip link add %s type veth peer name %s", hubVeth, clientVeth)
	sh(t, "ip link set %s netns %s", clientVeth, clientNS)
	sh(t, "ip addr add 10.99.0.1/30 dev %s && ip link set %s up", hubVeth, hubVeth)
	sh(t, "ip -n %s addr add 10.99.0.2/30 dev %s", clientNS, clientVeth)
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", clientNS, clientVeth, clientNS)

	keyFile := t.TempDir() + "/client.key"
	if err := os.WriteFile(keyFile, []byte(clientKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sh(t, "ip link add dev %s type wireguard && ip link set %s netns %s", clientLink, clientLink, clientNS)
	sh(t, "ip -n %s addr add %s dev %s", clientNS, clientAddress, clientLink)
	sh(t, "ip netns exec %s wg set %s private-key %s peer %q endpoint 10.99.0.1:%d allowed-ips 0.0.0.0/0 persistent-keepalive 5",
		clientNS, clientLink, keyFile, hubPublic, listenPort)
	sh(t, "ip -n %s link set %s up && ip -n %s route add default dev %s", clientNS, clientLink, clientNS, clientLink)

	probe := func() string {
		// A bare address avoids depending on DNS, which the hub does not serve yet.
		out, _ := exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace | grep '^ip=' || true", clientNS)).Output()
		if strings.TrimSpace(string(out)) == "" {
			return "BLOCKED"
		}
		return strings.TrimSpace(string(out))
	}
	return bed{
		apply: apply, probe: probe, applyWith: applyWith,
		uplink: uplink, secrets: secrets, clientHost: clientHost,
	}
}

func TestTrafficReachesTheInternetThroughTheHub(t *testing.T) {
	t.Log("client egress: " + newBed(t).waitForTraffic(t))
}

func TestDNSFollowsEachDevicesEgress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("DNS integration configures real namespaces and needs root")
	}
	for _, binary := range []string{"ip", "nft", "dnsmasq", "dig", "systemctl", "systemd-run", "conntrack"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}

	const (
		clientNamespace = "vhdnsclient"
		clientHostVeth  = "vdnsh"
		clientPeerVeth  = "vdnsc"
		clientGateway   = "10.180.0.1"
		clientA         = "10.180.0.2"
		clientB         = "10.180.0.3"
		publicName      = "same.public.test"
		privateName     = "app.private.test"
		privateMarker   = "10.183.0.80"
	)
	type fakeEgress struct {
		id               string
		namespace        string
		hostVeth         string
		peerVeth         string
		hostAddress      string
		namespaceAddress string
		authorityAddress string
		clientAddress    string
		markerAddress    string
		markerText       string
	}
	egresses := []fakeEgress{
		{
			id: "egress-a", namespace: "vhdnsa", hostVeth: "vdnsa", peerVeth: "uplink0",
			hostAddress: "10.181.0.1", namespaceAddress: "10.181.0.2",
			authorityAddress: "10.182.0.53", clientAddress: clientA,
			markerAddress: "192.0.2.10", markerText: "egress-a",
		},
		{
			id: "egress-b", namespace: "vhdnsb", hostVeth: "vdnsb", peerVeth: "uplink0",
			hostAddress: "10.181.0.5", namespaceAddress: "10.181.0.6",
			authorityAddress: "10.182.1.53", clientAddress: clientB,
			markerAddress: "198.51.100.20", markerText: "egress-b",
		},
	}
	private := fakeEgress{
		id: "private", namespace: "vhdnsp", hostVeth: "vdnsp", peerVeth: "uplink0",
		hostAddress: "10.181.0.9", namespaceAddress: "10.181.0.10",
		authorityAddress: "10.182.2.53",
	}
	units := []string{
		"vpn-hub-dns", "vpn-hub-resolver-public",
		"vpn-hub-resolver-client-egress-a", "vpn-hub-resolver-client-egress-b",
		"vpn-hub-resolver-public-egress-a", "vpn-hub-resolver-public-egress-b",
		"vpn-hub-resolver-net-private",
	}
	cleanup := func() {
		for _, unit := range units {
			try("systemctl stop %s.service", unit)
		}
		try("nft delete table inet vpn_hub")
		try("ip netns del %s", clientNamespace)
		try("ip link del %s", clientHostVeth)
		for _, egress := range append(append([]fakeEgress(nil), egresses...), private) {
			try("ip netns del %s", egress.namespace)
			try("ip link del %s", egress.hostVeth)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	sh(t, "ip netns add %s", clientNamespace)
	sh(t, "ip link add %s type veth peer name %s", clientHostVeth, clientPeerVeth)
	sh(t, "ip link set %s netns %s", clientPeerVeth, clientNamespace)
	sh(t, "ip addr add %s/24 dev %s && ip link set %s up", clientGateway, clientHostVeth, clientHostVeth)
	sh(t, "ip -n %s addr add %s/24 dev %s", clientNamespace, clientA, clientPeerVeth)
	sh(t, "ip -n %s addr add %s/24 dev %s", clientNamespace, clientB, clientPeerVeth)
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", clientNamespace, clientPeerVeth, clientNamespace)
	sh(t, "ip -n %s route add default via %s", clientNamespace, clientGateway)

	buildNamespace := func(item fakeEgress) {
		t.Helper()
		sh(t, "ip netns add %s", item.namespace)
		sh(t, "ip link add %s type veth peer name %s", item.hostVeth, item.peerVeth)
		sh(t, "ip link set %s netns %s", item.peerVeth, item.namespace)
		sh(t, "ip addr add %s/30 dev %s && ip link set %s up", item.hostAddress, item.hostVeth, item.hostVeth)
		sh(t, "ip -n %s addr add %s/30 dev %s", item.namespace, item.namespaceAddress, item.peerVeth)
		sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", item.namespace, item.peerVeth, item.namespace)
		sh(t, "ip -n %s addr add %s/32 dev lo", item.namespace, item.authorityAddress)
	}
	for _, egress := range egresses {
		buildNamespace(egress)
	}
	buildNamespace(private)

	startAuthority := func(namespace, address string, records ...string) {
		t.Helper()
		args := []string{
			"netns", "exec", namespace, "dnsmasq", "--keep-in-foreground", "--no-resolv",
			"--no-hosts", "--bind-interfaces", "--pid-file=/run/" + namespace + "-authority.pid",
			"--listen-address=" + address,
		}
		args = append(args, records...)
		command := exec.Command("ip", args...)
		var output bytes.Buffer
		command.Stdout = &output
		command.Stderr = &output
		if err := command.Start(); err != nil {
			t.Fatalf("start fake DNS authority in %s: %v", namespace, err)
		}
		t.Cleanup(func() {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		})
		for range 30 {
			response, err := exec.Command("ip", "netns", "exec", namespace, "dig", "+short", "+time=1", "+tries=1", "@"+address, recordsName(records)).Output()
			if err == nil && strings.TrimSpace(string(response)) != "" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("fake DNS authority in %s did not start:\n%s", namespace, output.String())
	}
	for _, egress := range egresses {
		startAuthority(egress.namespace, egress.authorityAddress,
			"--address=/"+publicName+"/"+egress.markerAddress,
			"--txt-record="+publicName+","+egress.markerText)
	}
	startAuthority(private.namespace, private.authorityAddress,
		"--address=/"+privateName+"/"+privateMarker,
		"--txt-record="+privateName+",private")

	firewallPlan := domain.FirewallPlan{
		IngressInterface: clientHostVeth,
		UplinkInterface:  "lo",
		ListenPort:       listenPort,
		ManagementPort:   22,
		ClientCIDR:       "10.180.0.0/24",
		DNSAddress:       clientGateway,
		Egresses: []domain.EgressGroup{
			{ID: egresses[0].id, Mark: 0x101, Interface: egresses[0].hostVeth, Addresses: []string{clientA}},
			{ID: egresses[1].id, Mark: 0x102, Interface: egresses[1].hostVeth, Addresses: []string{clientB}},
		},
		DNSDestinations: []domain.DNSDestination{
			{ClientAddresses: []string{clientA}, ResolverAddress: egresses[0].hostAddress},
			{ClientAddresses: []string{clientB}, ResolverAddress: egresses[1].hostAddress},
		},
		Internals: []domain.InternalNetwork{{
			TunnelID: private.id, Mark: 0x103, Interface: private.hostVeth,
			Clients: []string{clientA, clientB},
		}},
	}
	firewall := linux.NFTables{RuntimeDir: t.TempDir()}
	if _, err := firewall.Apply(context.Background(), firewallPlan); err != nil {
		t.Fatalf("apply DNS firewall: %v", err)
	}

	dnsPlan := domain.DNSPlan{
		ClientCIDR: "10.180.0.0/24",
		Zones: []domain.DNSZoneRoute{{
			Zone: privateName, Resolvers: []string{private.authorityAddress},
			ForwardAddress: private.namespaceAddress, Set: "internal_private",
		}},
		PrivateResolvers: []domain.DNSPrivateResolver{{
			TunnelID: private.id, Namespace: private.namespace, Address: private.namespaceAddress,
			Resolvers: []string{private.authorityAddress},
		}},
	}
	for _, egress := range egresses {
		dnsPlan.EgressResolvers = append(dnsPlan.EgressResolvers, domain.DNSEgressResolver{
			EgressID: egress.id, ClientAddresses: []string{egress.clientAddress},
			HubAddress: egress.hostAddress, Namespace: egress.namespace,
			NamespaceAddress: egress.namespaceAddress, PublicResolvers: []string{egress.authorityAddress},
		})
	}
	if err := (linux.Dnsmasq{ConfigDir: t.TempDir()}).Apply(context.Background(), dnsPlan, false); err != nil {
		t.Fatalf("apply DNS resolvers: %v", err)
	}

	query := func(source, name, queryType string, tcp bool, sourcePort ...int) string {
		t.Helper()
		args := []string{"netns", "exec", clientNamespace, "dig", "+short", "+time=1", "+tries=1"}
		if tcp {
			args = append(args, "+tcp")
		}
		if len(sourcePort) > 0 {
			source += fmt.Sprintf("#%d", sourcePort[0])
		}
		args = append(args, "-b", source, "@203.0.113.53", name, queryType)
		output, _ := exec.Command("ip", args...).Output()
		return strings.TrimSpace(string(output))
	}
	for _, egress := range egresses {
		for _, tcp := range []bool{false, true} {
			var address string
			for range 30 {
				address = query(egress.clientAddress, publicName, "A", tcp)
				if address == egress.markerAddress {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if address != egress.markerAddress {
				t.Fatalf("%s public DNS over TCP=%t returned %q, want %s", egress.id, tcp, address, egress.markerAddress)
			}
		}
		if text := query(egress.clientAddress, publicName, "TXT", false); !strings.Contains(text, egress.markerText) {
			t.Errorf("%s TXT marker = %q, want %q", egress.id, text, egress.markerText)
		}
		if address := query(egress.clientAddress, privateName, "A", false); address != privateMarker {
			t.Errorf("%s private DNS returned %q, want %s", egress.id, address, privateMarker)
		}
	}

	const fixedSourcePort = 53053
	if address := query(clientA, publicName, "A", false, fixedSourcePort); address != egresses[0].markerAddress {
		t.Fatalf("initial fixed-tuple DNS returned %q, want %s", address, egresses[0].markerAddress)
	}
	reassigned := firewallPlan
	reassigned.Egresses = append([]domain.EgressGroup(nil), firewallPlan.Egresses...)
	reassigned.Egresses[0].Addresses = nil
	reassigned.Egresses[1].Addresses = []string{clientA, clientB}
	reassigned.DNSDestinations = []domain.DNSDestination{{
		ClientAddresses: []string{clientA, clientB}, ResolverAddress: egresses[1].hostAddress,
	}}
	if _, err := firewall.Apply(context.Background(), reassigned); err != nil {
		t.Fatalf("reassign DNS egress: %v", err)
	}
	if address := query(clientA, publicName, "A", false, fixedSourcePort); address != egresses[1].markerAddress {
		t.Fatalf("reassigned fixed-tuple DNS returned %q, want %s", address, egresses[1].markerAddress)
	}
}

func recordsName(records []string) string {
	for _, record := range records {
		if value, found := strings.CutPrefix(record, "--address=/"); found {
			if index := strings.IndexByte(value, '/'); index >= 0 {
				return value[:index]
			}
		}
	}
	return "."
}

// The kill switch is the forward chain's drop policy: a client that is not in an
// egress set must be dropped, not fall through to the uplink.
func TestKillSwitchBlocksAnUnlistedClient(t *testing.T) {
	testbed := newBed(t)
	testbed.waitForTraffic(t)

	sh(t, "nft delete element inet vpn_hub client_direct '{ %s }'", clientHost)
	// Established flows would otherwise keep going via the conntrack rule.
	try("conntrack -D -s %s", clientHost)

	if result := testbed.probe(); result != "BLOCKED" {
		t.Fatalf("traffic leaked after the client left the egress set: %s", result)
	}
}

func TestKillSwitchBlocksWhenIngressIsDown(t *testing.T) {
	testbed := newBed(t)
	testbed.waitForTraffic(t)

	sh(t, "ip link set %s down", hubInterface)
	try("conntrack -D -s %s", clientHost)

	if result := testbed.probe(); result != "BLOCKED" {
		t.Fatalf("traffic leaked with the ingress interface down: %s", result)
	}
}

// Reconciling repeatedly must converge rather than rebuild, which would drop live
// client sessions.
func TestReapplyingKeepsTheSameInterface(t *testing.T) {
	testbed := newBed(t)
	testbed.waitForTraffic(t)

	before := sh(t, "ip -j link show %s | jq -r '.[0].ifindex'", hubInterface)
	testbed.apply(t)
	after := sh(t, "ip -j link show %s | jq -r '.[0].ifindex'", hubInterface)

	if before != after {
		t.Fatalf("the interface was recreated: ifindex %s became %s", before, after)
	}
	if result := testbed.probe(); result == "BLOCKED" {
		t.Fatal("traffic stopped after a repeated reconcile")
	}
}

// A hand-broken ruleset must be restored, which is what makes the agent a reconciler
// rather than a one-shot installer.
func TestDriftIsCorrected(t *testing.T) {
	testbed := newBed(t)
	testbed.waitForTraffic(t)

	// Match the name exactly. A substring also matches `inet vpn_hub_socks_<id>`,
	// one of which every tunnel now has, so a leftover from another scenario made
	// this read as "the table survived deletion" -- a failure with nothing to do
	// with drift.
	hubTables := func() string {
		return sh(t, "nft list tables | grep -cx 'table inet vpn_hub' || true")
	}

	sh(t, "nft delete table inet vpn_hub")
	if hubTables() != "0" {
		t.Fatal("the table survived deletion")
	}

	testbed.apply(t)
	if hubTables() == "0" {
		t.Fatal("the ruleset was not restored")
	}
	if result := testbed.probe(); result == "BLOCKED" {
		t.Fatal("traffic did not resume after the ruleset was restored")
	}
}

// A private network is reached by destination while the internet keeps flowing
// through the default egress. This is the milestone's whole claim, so it is checked
// against a real kernel rather than only a rendered ruleset.
func TestPrivateNetworkIsReachedAlongsideTheInternet(t *testing.T) {
	testbed := newBed(t)
	testbed.waitForTraffic(t)

	// A stand-in private network: a namespace with a service the hub can only reach
	// through the tunnel-shaped path being tested.
	const (
		privateNS   = "vpnhubcorp"
		privateVeth = "vhcorp"
		peerVeth    = "vccorp"
		service     = "10.20.0.80"
	)
	t.Cleanup(func() {
		try("ip netns del %s", privateNS)
		try("ip link del %s", privateVeth)
	})

	sh(t, "ip netns add %s", privateNS)
	sh(t, "ip link add %s type veth peer name %s", privateVeth, peerVeth)
	sh(t, "ip link set %s netns %s", peerVeth, privateNS)
	sh(t, "ip addr add 10.96.0.1/30 dev %s && ip link set %s up", privateVeth, privateVeth)
	sh(t, "ip -n %s addr add 10.96.0.2/30 dev %s", privateNS, peerVeth)
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", privateNS, peerVeth, privateNS)
	sh(t, "ip -n %s addr add %s/32 dev lo", privateNS, service)
	sh(t, "ip -n %s route add default via 10.96.0.1", privateNS)
	sh(t, "ip netns exec %s sysctl -qw net.ipv4.ip_forward=1", privateNS)

	// Route the private subnet through that namespace and let the client reach it,
	// mirroring what the reconciler builds for a private-network tunnel.
	sh(t, "ip route replace 10.20.0.0/24 via 10.96.0.2 dev %s", privateVeth)
	sh(t, "nft add rule inet vpn_hub forward iifname %q ip daddr 10.20.0.0/24 oifname %q accept",
		hubInterface, privateVeth)
	sh(t, "nft add rule inet vpn_hub postrouting ip saddr 10.80.0.0/24 oifname %q masquerade", privateVeth)

	// The stand-in service, kept alive well past the polling budget below and with
	// its output kept: a server that failed to start used to be indistinguishable
	// from a routing failure, because the goroutine dropped its error and the test
	// only ever said "not reachable".
	server := exec.Command("bash", "-c", fmt.Sprintf(
		"ip netns exec %s timeout 90 python3 -m http.server 80 --bind %s", privateNS, service))
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput
	if err := server.Start(); err != nil {
		t.Fatalf("start the stand-in private service: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})

	// Wait for it to be listening before asking the client, so a slow start is not
	// mistaken for a path that does not work.
	listening := false
	for range 30 {
		out, _ := exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s curl -s --max-time 2 -o /dev/null -w '%%{http_code}' http://%s/ || true",
			privateNS, service)).Output()
		if strings.TrimSpace(string(out)) == "200" {
			listening = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !listening {
		t.Fatalf("the stand-in private service never came up; its output was:\n%s\n%s",
			serverOutput.String(), diagnose(t))
	}

	reachable := func() bool {
		out, _ := exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s curl -s --max-time 6 -o /dev/null -w '%%{http_code}' http://%s/ || true",
			clientNS, service)).Output()
		return strings.TrimSpace(string(out)) == "200"
	}

	var reached bool
	for range 5 {
		if reached = reachable(); reached {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !reached {
		t.Fatalf("the private service is listening but the client cannot reach it\n%s\nservice output:\n%s",
			diagnose(t), serverOutput.String())
	}
	// The point of the milestone: both at once, not one instead of the other.
	if egress := testbed.probe(); egress == "BLOCKED" {
		t.Fatal("reaching the private network cost the client its internet")
	}
}

// A candidate must be proven before anything depends on it, and a failed one must
// leave nothing behind. Both are checked against a real kernel: the canary builds a
// namespace, and a namespace left over would break the next attempt.
func TestCanaryRejectsAnUnreachableCandidateAndCleansUp(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the canary builds a namespace and needs root")
	}
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box is not installed")
	}
	uplink := sh(t, "ip -j route show default | jq -r '.[0].dev'")
	if uplink == "" || uplink == "null" {
		t.Skip("no default route on this machine")
	}

	canary := linux.Canary{
		Egress:  linux.Egress{SecretsDir: t.TempDir(), DirectNamespaces: true},
		Timeout: 8 * time.Second,
	}
	t.Cleanup(func() {
		try("ip netns del vpn-hub-canary")
		try("ip link del vh-canary")
		try("nft delete table inet vpn_hub_canary")
		try("systemctl stop vpn-hub-proxy-canary.service")
	})

	// RFC 5737 documentation addresses: reserved for exactly this, and routed
	// nowhere.
	dead := []domain.ProxyTunnel{
		{Protocol: "vless", Server: "192.0.2.10", Port: 443, UUID: "00000000-0000-4000-8000-000000000001"},
		{Protocol: "vless", Server: "192.0.2.11", Port: 443, UUID: "00000000-0000-4000-8000-000000000002"},
	}

	chosen, reasons, err := canary.SelectCandidate(context.Background(), dead, uplink, nil)
	if err == nil {
		t.Fatalf("an unreachable candidate must not be promoted, got %+v", chosen)
	}
	if len(reasons) != len(dead) {
		t.Errorf("every candidate should be reported on, got %v", reasons)
	}

	// A namespace left behind would make the next refresh trip over it.
	if out := sh(t, "ip netns list | grep -c canary || true"); strings.TrimSpace(out) != "0" {
		t.Errorf("the canary namespace was left behind: %s", out)
	}
	if err := exec.Command("nft", "list", "table", "inet", "vpn_hub_canary").Run(); err == nil {
		t.Error("the temporary ruleset was left behind")
	}
}
