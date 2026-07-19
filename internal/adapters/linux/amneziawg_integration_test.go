//go:build integration

package linux_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	"vpn-hub/internal/domain"
)

// TestAmneziaWGEgressCarriesTrafficThroughObfuscation drives the real egress adapter
// against a stand-in AmneziaWG server, both using the amneziawg module and matching
// obfuscation parameters.
//
// This is what the unit tests cannot show: that the parameters the hub now sends
// actually let an obfuscated handshake complete. Driven as plain WireGuard -- which
// is what the code did before -- the two ends never agree and no packet passes. It
// needs the amneziawg kernel module, so it skips where the module is absent, which
// is every ephemeral CI runner; it is meant for a module-equipped host.
func TestAmneziaWGEgressCarriesTrafficThroughObfuscation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("builds real namespaces and needs root")
	}
	// The module check comes first, and on purpose. An ephemeral CI runner cannot
	// build the amneziawg DKMS module, so this test is meant to skip there -- but the
	// skip must read as "no module", which the CI guard ignores, not "awg is not
	// installed", which the guard treats as a runner that is missing something it
	// should have. So it never reaches the binary check on a machine without the
	// module.
	if err := exec.Command("bash", "-c", "ip link add awgprobe type amneziawg 2>/dev/null && ip link del awgprobe").Run(); err != nil {
		t.Skip("the amneziawg module is not available on this host, so an obfuscated tunnel cannot be built here")
	}
	for _, binary := range []string{"ip", "awg", "curl", "jq"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	uplink := sh(t, "ip -j route show default | jq -r '.[0].dev'")
	if uplink == "" || uplink == "null" {
		t.Skip("no default route")
	}

	// The obfuscation both ends must agree on. Wrong or missing, the handshake never
	// completes -- which is the whole point being tested.
	params := map[string]string{
		"Jc": "4", "Jmin": "40", "Jmax": "70", "S1": "30", "S2": "40",
		"H1": "1234567", "H2": "2345678", "H3": "3456789", "H4": "4567890",
	}
	awgParams := func() string {
		var parts []string
		for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"} {
			parts = append(parts, key+" "+params[strings.ToUpper(key[:1])+key[1:]])
		}
		return strings.Join(parts, " ")
	}()

	const (
		serverNS   = "siawg"
		serverVeth = "vsiawg"
		serverPeer = "vspawg"
		serverPort = 52820
	)
	cleanup := func() {
		try("systemctl stop vpn-hub-socks-amz.service")
		try("nft delete table inet vpn_hub_socks_amz")
		try("ip netns del %s", serverNS)
		try("ip link del %s", serverVeth)
		try("ip netns del vpn-hub-amz")
		try("ip link del vh-amz")
		try("ip rule del fwmark 0x101 lookup 100")
	}
	cleanup()
	t.Cleanup(cleanup)

	serverKey := sh(t, "awg genkey")
	serverPublic := sh(t, "echo %q | awg pubkey", serverKey)
	hubKey := sh(t, "awg genkey")
	hubPublic := sh(t, "echo %q | awg pubkey", hubKey)

	// The stand-in AmneziaWG server, in a namespace, obfuscation and all.
	sh(t, "ip netns add %s", serverNS)
	sh(t, "ip link add %s type veth peer name %s", serverVeth, serverPeer)
	sh(t, "ip link set %s netns %s", serverPeer, serverNS)
	sh(t, "ip addr add 10.94.0.1/30 dev %s && ip link set %s up", serverVeth, serverVeth)
	sh(t, "ip -n %s addr add 10.94.0.2/30 dev %s", serverNS, serverPeer)
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", serverNS, serverPeer, serverNS)

	serverKeyFile := filepath.Join(t.TempDir(), "server.key")
	sh(t, "printf '%%s\\n' %q > %s && chmod 600 %s", serverKey, serverKeyFile, serverKeyFile)
	sh(t, "ip netns exec %s ip link add awg0 type amneziawg", serverNS)
	sh(t, "ip netns exec %s awg set awg0 private-key %s listen-port %d %s peer %q allowed-ips 10.73.0.2/32",
		serverNS, serverKeyFile, serverPort, awgParams, hubPublic)
	sh(t, "ip -n %s addr add 10.73.0.1/24 dev awg0 && ip -n %s link set awg0 up", serverNS, serverNS)
	// Its own way out, towards the host, or the traffic it forwards has nowhere to go.
	sh(t, "ip -n %s route add default via 10.94.0.1", serverNS)
	// It routes its client to the internet, as a provider would.
	sh(t, "ip netns exec %s sysctl -qw net.ipv4.ip_forward=1", serverNS)
	sh(t, "ip netns exec %s nft add table ip nat", serverNS)
	sh(t, "ip netns exec %s nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; }'", serverNS)
	sh(t, "ip netns exec %s nft add rule ip nat postrouting ip saddr 10.73.0.0/24 oifname %q masquerade", serverNS, serverPeer)
	// The host forwards for the stand-in and translates it out the uplink.
	sh(t, "sysctl -qw net.ipv4.ip_forward=1")
	sh(t, "iptables -t nat -A POSTROUTING -s 10.94.0.0/30 -o %s -j MASQUERADE", uplink)

	// The hub dials it through the real egress adapter, with the same parameters
	// coming from the parsed provider config.
	egress := linux.Egress{SecretsDir: t.TempDir(), DirectNamespaces: true}
	spec := domain.EgressSpec{
		TunnelID: "amz", Namespace: "vpn-hub-amz",
		HostVeth: "vh-amz", PeerVeth: "uplink0",
		HostAddress: "10.90.0.1/30", PeerAddress: "10.90.0.2/30",
		Mark: 0x101, RouteTable: 100, ClientCIDR: "10.80.0.0/24",
		Interface: "wg0",
		Type:      domain.TunnelAmneziaWG,
		Tunnel: domain.WireGuardTunnel{
			PrivateKey: hubKey,
			Addresses:  []string{"10.73.0.2/32"},
			Parameters: params,
			Peer: domain.WireGuardPeer{
				PublicKey:  serverPublic,
				Endpoint:   fmt.Sprintf("10.94.0.2:%d", serverPort),
				AllowedIPs: []string{"0.0.0.0/0"},
				Keepalive:  5,
			},
		},
	}
	if err := egress.Apply(context.Background(), []domain.EgressSpec{spec}); err != nil {
		t.Fatalf("the AmneziaWG egress did not come up: %v", err)
	}

	// The handshake is the proof: it only completes if the obfuscation matched.
	var reached bool
	for range 12 {
		out, _ := exec.Command("bash", "-c",
			"ip netns exec vpn-hub-amz curl -s --max-time 5 https://1.1.1.1/cdn-cgi/trace | grep '^ip=' || true").Output()
		if strings.Contains(string(out), "ip=") {
			reached = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !reached {
		state, _ := exec.Command("bash", "-c", "ip netns exec vpn-hub-amz awg show 2>&1; ip netns exec siawg awg show 2>&1").CombinedOutput()
		t.Fatalf("no traffic passed through the obfuscated tunnel -- the handshake never completed:\n%s", state)
	}

	// And the handshake is visible through awg, not wg.
	handshake := sh(t, "ip netns exec vpn-hub-amz awg show wg0 latest-handshakes")
	if !strings.Contains(handshake, serverPublic) {
		t.Errorf("awg does not report a handshake with the provider:\n%s", handshake)
	}
	if _, err := exec.Command("bash", "-c", "ip netns exec vpn-hub-amz wg show wg0 2>&1").Output(); err == nil {
		// wg on an amneziawg device returns an error; if it somehow succeeds the
		// device was created plain, which would mean obfuscation was skipped.
		if out, _ := exec.Command("bash", "-c", "ip netns exec vpn-hub-amz wg show wg0 dump 2>&1").CombinedOutput(); !strings.Contains(string(out), "not supported") && strings.TrimSpace(string(out)) != "" {
			t.Logf("note: wg could read the device; confirm it is genuinely amneziawg")
		}
	}
}
