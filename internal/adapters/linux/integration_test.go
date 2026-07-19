//go:build integration

// These tests create real network namespaces, veth pairs, WireGuard interfaces and
// nftables rulesets, so they need root and a Linux kernel and sit behind a build tag.
//
// They drive the production path: the same plan builder, ingress adapter and firewall
// adapter the agent uses. They deliberately use plain WireGuard rather than
// AmneziaWG -- the obfuscation parameters aside the protocol is identical, and the
// AmneziaWG module is built by DKMS, which an ephemeral CI runner cannot do. What is
// under test is the hub's own machinery: ruleset, NAT, peer synchronisation and the
// kill switch, none of which depends on the obfuscation.
package linux_test

import (
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
	t.Fatalf("no traffic reached the internet\n%s", sh(t, "nft list table inet vpn_hub"))
	return ""
}

func newBed(t *testing.T) bed {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests configure real interfaces and need root")
	}
	for _, binary := range []string{"ip", "nft", "wg", "jq", "curl"} {
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
			ID: "laptop",
			Profiles: []domain.DeployedProfile{{
				ID: "laptop-direct", Egress: domain.EgressDirect,
				Address: clientAddress, ClientPublicKey: clientPublic,
			}},
		}},
	}

	secrets := t.TempDir()
	apply := func(t *testing.T) {
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

		if err := (linux.NFTables{}).Apply(context.Background(), plan); err != nil {
			t.Fatalf("apply ruleset: %v", err)
		}
		ingress := linux.Ingress{SecretsDir: secrets, LinkType: "wireguard", Tool: "wg"}
		if err := ingress.Apply(context.Background(), spec); err != nil {
			t.Fatalf("apply ingress: %v", err)
		}
	}
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
	return bed{apply: apply, probe: probe}
}

func TestTrafficReachesTheInternetThroughTheHub(t *testing.T) {
	t.Log("client egress: " + newBed(t).waitForTraffic(t))
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

	sh(t, "nft delete table inet vpn_hub")
	if sh(t, "nft list tables | wc -l") != "0" {
		t.Fatal("the table survived deletion")
	}

	testbed.apply(t)
	if sh(t, "nft list tables | wc -l") == "0" {
		t.Fatal("the ruleset was not restored")
	}
	if result := testbed.probe(); result == "BLOCKED" {
		t.Fatal("traffic did not resume after the ruleset was restored")
	}
}
