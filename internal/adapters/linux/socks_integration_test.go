//go:build integration

package linux_test

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	"vpn-hub/internal/domain"
)

const (
	providerNS   = "vpnhubprov"
	providerVeth = "vhprov"
	providerPeer = "vcprov"
	providerPort = 51822

	egressID = "nl"
	egressNS = "vpn-hub-" + egressID
	egressLo = "vh-" + egressID
	socksAt  = "10.90.0.1"
	socksIn  = "10.90.0.2"
	socksOn  = 11080
)

// standInProvider builds a WireGuard server in a namespace of its own and returns
// its public key.
//
// A provider on the same machine cannot prove that traffic leaves by a different
// address -- that needs a second host and was checked on the lab. What it does prove
// is everything the hub is responsible for: that the namespace is built, that the
// tunnel comes up inside it, and that the proxy in it is reachable by exactly the
// clients the revision permits and no others.
func standInProvider(t *testing.T, uplink, peerPublicKey string) string {
	t.Helper()
	t.Cleanup(func() {
		try("ip netns del %s", providerNS)
		try("ip link del %s", providerVeth)
	})

	key := sh(t, "wg genkey")
	public := sh(t, "echo %q | wg pubkey", key)

	sh(t, "ip netns add %s", providerNS)
	sh(t, "ip link add %s type veth peer name %s", providerVeth, providerPeer)
	sh(t, "ip link set %s netns %s", providerPeer, providerNS)
	sh(t, "ip addr add 10.98.0.1/30 dev %s && ip link set %s up", providerVeth, providerVeth)
	sh(t, "ip -n %s addr add 10.98.0.2/30 dev %s", providerNS, providerPeer)
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", providerNS, providerPeer, providerNS)
	sh(t, "ip -n %s route add default via 10.98.0.1", providerNS)

	keyFile := t.TempDir() + "/provider.key"
	sh(t, "printf '%%s\\n' %q > %s && chmod 600 %s", key, keyFile, keyFile)
	// Created inside the namespace, not moved into it: a WireGuard device keeps its
	// socket wherever it was created, so a provider built the way the hub builds its
	// own tunnels would listen in the main namespace and answer nobody.
	sh(t, "ip netns exec %s ip link add wg0 type wireguard", providerNS)
	sh(t, "ip netns exec %s wg set wg0 private-key %s listen-port %d peer %q allowed-ips 10.7.0.0/24",
		providerNS, keyFile, providerPort, peerPublicKey)
	sh(t, "ip -n %s addr add 10.7.0.1/24 dev wg0", providerNS)
	sh(t, "ip -n %s link set wg0 up", providerNS)

	// The provider routes its clients to the internet, as a real one would.
	sh(t, "ip netns exec %s sysctl -qw net.ipv4.ip_forward=1", providerNS)
	sh(t, "ip netns exec %s nft add table ip nat", providerNS)
	sh(t, "ip netns exec %s nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; }'", providerNS)
	sh(t, "ip netns exec %s nft add rule ip nat postrouting ip saddr 10.7.0.0/24 oifname %q masquerade",
		providerNS, providerPeer)

	// And the hub forwards for it. The hub's own policy is drop, so without this the
	// stand-in provider could not reach anything -- which is the same constraint a
	// real deployment puts on the machine.
	sh(t, "nft add rule inet vpn_hub forward iifname %q oifname %q accept", providerVeth, uplink)
	// Out of the uplink, which is where this traffic is going -- not back down the
	// link it arrived on.
	sh(t, "nft add rule inet vpn_hub postrouting ip saddr 10.98.0.0/30 oifname %q masquerade", uplink)
	return public
}

// TestSocksEndpointServesOnlyPermittedDevices drives the production egress adapter:
// a real namespace, a real WireGuard tunnel inside it, a real microsocks, and the
// rendered ruleset deciding who may reach it.
//
// Until this existed, nothing in CI built an egress namespace at all -- the only
// test that reached applyOne was the canary, which asserts a failure and stops
// before the namespace is finished. So the namespace default route, the NAT inside
// it, the policy routing and the SOCKS endpoint were exercised on a real kernel
// exactly never.
func TestSocksEndpointServesOnlyPermittedDevices(t *testing.T) {
	for _, binary := range []string{"microsocks", "systemd-run"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	testbed := newBed(t)
	testbed.waitForTraffic(t)

	tunnelKey := sh(t, "wg genkey")
	tunnelPublic := sh(t, "echo %q | wg pubkey", tunnelKey)
	providerPublic := standInProvider(t, testbed.uplink, tunnelPublic)

	egress := linux.Egress{SecretsDir: testbed.secrets, DirectNamespaces: true}
	t.Cleanup(func() {
		try("systemctl stop vpn-hub-socks-%s.service", egressID)
		try("nft delete table inet vpn_hub_socks_%s", egressID)
		try("ip netns del %s", egressNS)
		try("ip link del %s", egressLo)
		try("ip rule del fwmark 0x101")
	})

	spec := domain.EgressSpec{
		TunnelID: egressID, Namespace: egressNS,
		HostVeth: egressLo, PeerVeth: "uplink0",
		HostAddress: socksAt + "/30", PeerAddress: socksIn + "/30",
		Mark: 0x101, RouteTable: 101, ClientCIDR: "10.80.0.0/24",
		Interface: "wg0", SocksPort: socksOn,
		Type: domain.TunnelWireGuard,
		Tunnel: domain.WireGuardTunnel{
			PrivateKey: tunnelKey,
			Addresses:  []string{"10.7.0.2/32"},
			Peer: domain.WireGuardPeer{
				PublicKey:  providerPublic,
				Endpoint:   fmt.Sprintf("10.98.0.2:%d", providerPort),
				AllowedIPs: []string{"0.0.0.0/0"},
				Keepalive:  5,
			},
		},
	}
	if err := egress.Apply(context.Background(), []domain.EgressSpec{spec}); err != nil {
		t.Fatalf("build the egress namespace: %v", err)
	}

	endpoint := domain.SocksEndpoint{
		TunnelID: egressID, Address: socksAt, Interface: egressLo, Port: socksOn,
		Clients: []string{testbed.clientHost},
	}
	testbed.applyWith(t, func(plan *domain.FirewallPlan) {
		plan.Socks = []domain.SocksEndpoint{endpoint}
	})
	// Reapplying the hub's table drops the rules the stand-in provider needs, since
	// they are not part of any plan.
	sh(t, "nft add rule inet vpn_hub forward iifname %q oifname %q accept", providerVeth, testbed.uplink)
	sh(t, "nft add rule inet vpn_hub postrouting ip saddr 10.98.0.0/30 oifname %q masquerade", testbed.uplink)

	through := func() string {
		out, _ := exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s curl -s --max-time 8 --socks5 %s:%d https://1.1.1.1/cdn-cgi/trace | grep '^ip=' || true",
			clientNS, socksAt, socksOn)).Output()
		if strings.TrimSpace(string(out)) == "" {
			return "BLOCKED"
		}
		return strings.TrimSpace(string(out))
	}

	var served string
	for range 6 {
		if served = through(); served != "BLOCKED" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if served == "BLOCKED" {
		t.Fatalf("a permitted device could not reach the endpoint\n%s\n%s", socksDiagnosis(t), diagnose(t))
	}

	// The other half, and the one that matters more: an endpoint that admitted
	// everyone would be a way around the egress each device was given.
	testbed.applyWith(t, func(plan *domain.FirewallPlan) {
		refused := endpoint
		refused.Clients = nil
		plan.Socks = []domain.SocksEndpoint{refused}
	})
	if still := through(); still != "BLOCKED" {
		t.Errorf("a device the revision does not permit still reached the endpoint: %s", still)
	}
}

// socksDiagnosis separates the ways the endpoint can fail: no proxy, no forwarding,
// or a tunnel that never came up.
func socksDiagnosis(t *testing.T) string {
	t.Helper()
	var report strings.Builder
	for _, step := range []struct{ title, command string }{
		{"proxy unit", "systemctl is-active vpn-hub-socks-" + egressID + ".service"},
		{"proxy listening", "ip netns exec " + egressNS + " ss -tlnp"},
		{"tunnel", "ip netns exec " + egressNS + " wg show"},
		{"namespace routes", "ip -n " + egressNS + " route"},
		{"namespace reaches the internet", "ip netns exec " + egressNS + " ping -c2 -W2 1.1.1.1"},
		{"dnat table", "nft list table inet vpn_hub_socks_" + egressID},
	} {
		output, _ := exec.Command("bash", "-c", step.command+" 2>&1").CombinedOutput()
		fmt.Fprintf(&report, "\n--- %s ---\n%s", step.title, output)
	}
	return report.String()
}
