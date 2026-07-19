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

func egressSpec() domain.EgressSpec {
	return domain.EgressSpec{
		TunnelID: "corp", Namespace: "vpn-hub-corp",
		HostVeth: "vh-corp", PeerVeth: "uplink0",
		HostAddress: "10.90.0.1/30", PeerAddress: "10.90.0.2/30",
		Mark: 0x101, RouteTable: 100, ClientCIDR: "10.80.0.0/24",
		Interface: "wg0",
		Tunnel: domain.WireGuardTunnel{
			PrivateKey: "cOFA+ItsMPRFpKt4kPsUlqUlkxHnFvJdWuBK5rXqL0Y=",
			Addresses:  []string{"10.7.0.5/32"},
			Peer: domain.WireGuardPeer{
				PublicKey: "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=",
				Endpoint:  "provider.example:51820",
			},
		},
	}
}

// The agent keeps a private mount namespace, where a namespace bind mount would be
// confined and unusable. Delegating to a transient unit is what lets the sandbox stay
// on, so it is worth asserting rather than leaving to a comment.
func TestNamespaceCreationIsDelegatedToATransientUnit(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"ip -j netns list": "[]"}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	_ = egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()})

	if !host.ran("systemd-run --quiet --wait --collect --unit=vpn-hub-netns-add-vpn-hub-corp ip netns add") {
		t.Fatalf("namespace creation was not delegated; commands: %v", host.commands)
	}
	for _, command := range host.commands {
		if strings.HasPrefix(command, "ip netns add") {
			t.Fatalf("namespace created directly, which the sandbox would confine: %s", command)
		}
	}
}

// Integration tests and systemd-less hosts have no sandbox to escape.
func TestDirectNamespacesSkipsTheDelegation(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"ip -j netns list": "[]"}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir(), DirectNamespaces: true}

	_ = egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()})

	if !host.ran("ip netns add vpn-hub-corp") {
		t.Fatalf("expected a direct call; commands: %v", host.commands)
	}
	if host.ran("systemd-run") {
		t.Fatal("delegation should be skipped when it buys nothing")
	}
}

// A namespace the revision no longer names has to go, and its removal is a mount
// operation too.
func TestStaleNamespacesAreRemovedThroughTheSameRoute(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{
		"ip -j netns list": `[{"name":"vpn-hub-gone"},{"name":"unrelated"}]`,
	}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("--unit=vpn-hub-netns-del-vpn-hub-gone ip netns del") {
		t.Fatalf("the stale namespace was not removed; commands: %v", host.commands)
	}
	// Namespaces the hub did not create are none of its business.
	if host.ran("unrelated") {
		t.Fatal("a namespace outside the hub's prefix was touched")
	}
}

// errNotRunning stands in for systemctl reporting an inactive unit.
var errNotRunning = errors.New("inactive")

// workingHost answers everything a WireGuard egress needs to converge.
//
// Without the dump reply Apply fails partway, and three tests here used to discard
// that error — so everything past the failure point was exercised by nothing at all,
// including both halves of the kill switch.
func workingHost(namespaces string) *fakeHost {
	return &fakeHost{replies: map[string]string{
		"ip -j netns list": namespaces,
		"ip netns exec vpn-hub-corp wg show wg0 dump": "privkey\tpubkey\t51820\toff\n" +
			"TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=\t(none)\tprovider.example:51820\t0.0.0.0/0\t0\t0\t0\toff\n",
	}}
}

// The namespace has no route out except through the tunnel interface. That is the
// second kill switch, independent of the forward policy: when the tunnel goes down
// packets die inside the namespace rather than finding another way out.
func TestTheNamespaceRoutesOnlyThroughTheTunnel(t *testing.T) {
	t.Parallel()
	host := workingHost("[]")
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("ip -n vpn-hub-corp route replace default dev wg0") {
		t.Fatalf("the namespace has no default route through the tunnel; commands: %v", host.commands)
	}
}

// Inside the namespace the client address is translated to the one the provider
// issued. Without it the provider receives packets from an address it does not route
// and the tunnel appears to work while carrying nothing.
func TestTrafficLeavesTheNamespaceTranslated(t *testing.T) {
	t.Parallel()
	host := workingHost("[]")
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var applied bool
	for _, command := range host.commands {
		if strings.Contains(command, "nft-in-netns vpn-hub-corp") && strings.Contains(command, "masquerade") {
			applied = true
		}
	}
	if !applied {
		t.Fatalf("no ruleset was applied inside the namespace; commands: %v", host.commands)
	}
}

// The mark the packet filter sets has to select this tunnel's routing table. Without
// the rule the lookup falls through to the main table and the traffic leaves by the
// hub's own uplink — past the tunnel it was marked for.
func TestTheMarkSelectsTheTunnelsRoutingTable(t *testing.T) {
	t.Parallel()
	host := workingHost("[]")
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("ip route replace default via 10.90.0.2 dev vh-corp table 100") {
		t.Fatalf("the routing table has no default; commands: %v", host.commands)
	}
	if !host.ran("ip rule add fwmark 0x101 lookup 100") {
		t.Fatalf("nothing sends the marked traffic to that table; commands: %v", host.commands)
	}
}

// Routing is in place before the tunnel is brought up. The other order leaves a
// window where the mark exists and its table does not, so the lookup fails and the
// packet falls back to the main table — for traffic the hub originates, that means a
// private-zone query leaving in clear over the internet.
func TestRoutingIsInPlaceBeforeTheTunnel(t *testing.T) {
	t.Parallel()
	host := workingHost("[]")
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	routed, raised := -1, -1
	for index, command := range host.commands {
		if routed < 0 && strings.Contains(command, "route replace default via 10.90.0.2") {
			routed = index
		}
		if raised < 0 && strings.Contains(command, "wg set wg0") {
			raised = index
		}
	}
	if routed < 0 || raised < 0 {
		t.Fatalf("expected both steps; commands: %v", host.commands)
	}
	if routed > raised {
		t.Errorf("the tunnel came up before its route existed: route at %d, tunnel at %d", routed, raised)
	}
}

// One unreachable provider must not stop a withdrawn one from being taken down.
// Returning at the first failure meant decommissioning any tunnel silently depended
// on every other tunnel being healthy.
func TestAFailingTunnelStillLetsAStaleOneBeRemoved(t *testing.T) {
	t.Parallel()
	host := workingHost(`[{"name":"vpn-hub-gone"}]`)
	host.failures = map[string]error{
		"ip -n vpn-hub-corp link set wg0 up": errors.New("provider unreachable"),
	}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	err := egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()})
	if err == nil {
		t.Fatal("the failure was not reported")
	}
	if !host.ran("--unit=vpn-hub-netns-del-vpn-hub-gone ip netns del") {
		t.Fatalf("the withdrawn tunnel kept its namespace; commands: %v", host.commands)
	}
}

// A namespace being taken down may be the one the public resolver lives in. Deleting
// a namespace does not kill what runs inside it, so a resolver left behind keeps
// answering in a namespace that no longer exists while the hub forwards to an address
// that now leads somewhere else — public DNS stops for every client and does not
// recover on its own.
func TestRemovingANamespaceTakesTheResolverWithIt(t *testing.T) {
	t.Parallel()
	host := workingHost(`[{"name":"vpn-hub-gone"}]`)
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("systemctl stop " + upstreamResolverUnit) {
		t.Fatalf("the resolver was left running; commands: %v", host.commands)
	}
}

// Failing to list namespaces is not the same as there being none. Reading it as an
// empty host stopped collection silently: a withdrawn provider kept its namespace,
// its tunnel and its live session, and Apply returned success.
func TestAFailedObservationIsNotAnEmptyHost(t *testing.T) {
	t.Parallel()
	host := &fakeHost{failures: map[string]error{"ip -j netns list": errors.New("permission denied")}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if _, err := egress.Observe(context.Background()); err == nil {
		t.Fatal("a failed listing was reported as an empty host")
	}
}

// A secret must not outlive the configuration that justified it. Withdrawing a
// provider — or merely disabling its tunnel, which drops it from the revision —
// used to leave its private key, its pre-shared key, its sing-box UUID and its
// OpenVPN inline certificates on disk until a reboot cleared the tmpfs.
func TestRemovingATunnelRemovesItsSecrets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"gone-private.key", "gone-psk.key", "gone-singbox.json", "gone-openvpn.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := workingHost(`[{"name":"vpn-hub-gone"}]`)

	if err := (Egress{Run: host.run, SecretsDir: dir}).Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range left {
		t.Errorf("%s outlived the tunnel it belonged to", entry.Name())
	}
}

// `ip netns del` knows nothing about routing rules, so the rule and the table a
// tunnel installed outlive it. They accumulate across reconciles, and a rule naming
// an emptied table is a lookup that falls through to the main table — the difference
// between a packet dying inside a namespace and a packet leaving by the hub's own
// uplink. Found on the lab, where one survived the tunnel by hours.
func TestRemovingATunnelTakesItsPolicyRoutingWithIt(t *testing.T) {
	t.Parallel()
	host := workingHost(`[{"name":"vpn-hub-gone"}]`)
	host.replies["ip rule show"] = "0:\tfrom all lookup local\n" +
		"1000:\tfrom all fwmark 0x101 lookup 101\n" +
		"1000:\tfrom all fwmark 0x102 lookup 102\n" +
		"32766:\tfrom all lookup main\n"
	host.replies["ip route show table 101"] = "default via 10.90.0.2 dev vh-gone\n"
	host.replies["ip route show table 102"] = "default via 10.90.0.6 dev vh-other\n"
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("ip rule del fwmark 0x101 lookup 101") {
		t.Fatalf("the rule outlived its tunnel; commands: %v", host.commands)
	}
	if !host.ran("ip route flush table 101") {
		t.Errorf("the routing table outlived its tunnel; commands: %v", host.commands)
	}
	// And nothing belonging to a tunnel that is still in service.
	if host.ran("ip rule del fwmark 0x102") || host.ran("ip route flush table 102") {
		t.Errorf("another tunnel's routing was torn down; commands: %v", host.commands)
	}
}

func amneziaSpec() domain.EgressSpec {
	spec := egressSpec()
	spec.Type = domain.TunnelAmneziaWG
	spec.Tunnel.Parameters = map[string]string{
		"Jc": "4", "Jmin": "40", "Jmax": "70", "S1": "30", "S2": "40",
		"H1": "1234567", "H2": "2345678", "H3": "3456789", "H4": "4567890",
	}
	return spec
}

// AmneziaWG is obfuscated WireGuard: a different kernel module with its own netlink
// family, so a different device type and a different tool. Driven as plain WireGuard
// -- which is what the code did -- the peer waits for obfuscated packets the hub
// never sends, and the handshake never completes. This asserts the three things that
// were wrong.
func TestAmneziaWGEgressUsesTheAmneziaToolAndType(t *testing.T) {
	t.Parallel()
	host := workingHost("[]")
	// The interface is absent, so the creation path runs -- which is where the
	// device type is chosen.
	host.failures = map[string]error{"ip -n vpn-hub-corp link show wg0": errNotRunning}
	// awg, not wg, reports the peer so removeOtherPeers can read it.
	host.replies["ip netns exec vpn-hub-corp awg show wg0 dump"] =
		host.replies["ip netns exec vpn-hub-corp wg show wg0 dump"]
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), []domain.EgressSpec{amneziaSpec()}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("ip link add wg0 type amneziawg") {
		t.Errorf("the device was not created as amneziawg; commands: %v", host.commands)
	}
	if host.ran("ip link add wg0 type wireguard") {
		t.Error("a plain wireguard device was created for an AmneziaWG tunnel")
	}
	var configured bool
	for _, command := range host.commands {
		if strings.Contains(command, "awg set wg0 private-key") {
			configured = true
			// The obfuscation parameters must reach the tool, and before `peer`,
			// since they are interface-level settings.
			for _, want := range []string{"jc 4", "jmin 40", "h1 1234567", "s1 30"} {
				if !strings.Contains(command, want) {
					t.Errorf("parameter %q did not reach awg: %s", want, command)
				}
			}
			if strings.Index(command, "peer") < strings.Index(command, "jc 4") {
				t.Errorf("obfuscation parameters came after peer, where awg ignores them: %s", command)
			}
		}
		if strings.Contains(command, "wg set wg0") && !strings.Contains(command, "awg set wg0") {
			t.Errorf("the plain wg tool was used for an AmneziaWG tunnel: %s", command)
		}
	}
	if !configured {
		t.Fatalf("awg set was never called; commands: %v", host.commands)
	}
}

// Plain WireGuard must keep using wg and type wireguard, with no obfuscation noise.
func TestPlainWireGuardEgressIsUnchanged(t *testing.T) {
	t.Parallel()
	host := workingHost("[]")
	host.failures = map[string]error{"ip -n vpn-hub-corp link show wg0": errNotRunning}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("ip link add wg0 type wireguard") {
		t.Errorf("plain WireGuard changed device type; commands: %v", host.commands)
	}
	for _, command := range host.commands {
		if strings.Contains(command, "awg") || strings.Contains(command, "jc ") {
			t.Errorf("obfuscation leaked into a plain WireGuard tunnel: %s", command)
		}
	}
}
