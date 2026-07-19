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

// standInSingBox runs a VLESS server on sing-box in a namespace and returns the
// vless:// link a client dials it with.
//
// Plain VLESS, no TLS: the transport and the obfuscation are sing-box's concern, and
// what the hub is responsible for is the same either way -- a tun inbound, a marked
// outbound, and the namespace routing that keeps sing-box's own connection from
// looping into the device it serves. REALITY is deliberately not exercised here: it
// never completed a handshake on the lab even client-and-server on one machine, so
// claiming a passing REALITY test would be claiming something not shown.
func standInSingBox(t *testing.T, uplink, uuid string) string {
	t.Helper()
	const (
		ns   = "sisb"
		veth = "vsisb"
		peer = "vspsb"
		port = 18443
		net4 = "10.96.0"
	)
	t.Cleanup(func() {
		try("systemctl stop sisb-server.service")
		try("ip netns del %s", ns)
		try("ip link del %s", veth)
	})

	sh(t, "ip netns add %s", ns)
	sh(t, "ip link add %s type veth peer name %s", veth, peer)
	sh(t, "ip link set %s netns %s", peer, ns)
	sh(t, "ip addr add %s.1/30 dev %s && ip link set %s up", net4, veth, veth)
	sh(t, "ip -n %s addr add %s.2/30 dev %s", ns, net4, peer)
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", ns, peer, ns)
	sh(t, "ip -n %s route add default via %s.1", ns, net4)

	dir := t.TempDir()
	serverConf := filepath.Join(dir, "server.json")
	sh(t, `cat > %s <<'EOF'
{
  "log": { "level": "warn" },
  "inbounds": [{
    "type": "vless",
    "listen": "%s.2",
    "listen_port": %d,
    "users": [{ "uuid": "%s" }]
  }],
  "outbounds": [{ "type": "direct" }]
}
EOF`, serverConf, net4, port, uuid)

	// The server reaches the internet like any other stand-in provider.
	sh(t, "ip netns exec %s sysctl -qw net.ipv4.ip_forward=1", ns)
	sh(t, "sysctl -qw net.ipv4.ip_forward=1")
	sh(t, "iptables -t nat -C POSTROUTING -s %s.0/30 -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s.0/30 -o %s -j MASQUERADE", net4, uplink, net4, uplink)

	sh(t, "systemd-run --quiet --collect --unit=sisb-server ip netns exec %s sing-box run -c %s", ns, serverConf)

	// The link a provider would hand over: plain VLESS over TCP, encryption none.
	return fmt.Sprintf("vless://%s@%s.2:%d?type=tcp&encryption=none#standin", uuid, net4, port)
}

// TestSingBoxEgressCarriesTraffic drives the real egress adapter against that server:
// sing-box under systemd inside the namespace, presenting a tun device ordinary
// routing sends packets to, its own connection to the provider marked so it leaves by
// the veth rather than looping into its own tun. M7 had no live scenario; this is one.
func TestSingBoxEgressCarriesTraffic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("builds real namespaces and needs root")
	}
	for _, binary := range []string{"ip", "sing-box", "curl", "jq"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	uplink := sh(t, "ip -j route show default | jq -r '.[0].dev'")
	if uplink == "" || uplink == "null" {
		t.Skip("no default route")
	}

	cleanup := func() {
		try("systemctl stop vpn-hub-proxy-sb.service")
		try("ip netns del vpn-hub-sb")
		try("ip link del vh-sb")
		try("ip rule del fwmark 0x101 lookup 100")
	}
	cleanup()
	t.Cleanup(cleanup)

	const uuid = "b7e3f8a1-2c4d-4e6f-8a1b-3c5d7e9f0a2b"
	link := standInSingBox(t, uplink, uuid)
	parsed, err := linux.ParseVLESS(link)
	if err != nil {
		t.Fatalf("the stand-in produced a link the hub cannot parse: %v", err)
	}

	egress := linux.Egress{SecretsDir: t.TempDir(), DirectNamespaces: true}
	spec := domain.EgressSpec{
		TunnelID: "sb", Namespace: "vpn-hub-sb",
		HostVeth: "vh-sb", PeerVeth: "uplink0",
		HostAddress: "10.90.0.1/30", PeerAddress: "10.90.0.2/30",
		Mark: 0x101, RouteTable: 100, ClientCIDR: "10.80.0.0/24",
		Interface: linux.SingBoxTunInterface,
		Type:      domain.TunnelXray,
		Proxy:     parsed,
	}
	if err := egress.Apply(context.Background(), []domain.EgressSpec{spec}); err != nil {
		t.Fatalf("the sing-box egress did not come up: %v", err)
	}

	var reached bool
	for range 20 {
		out, _ := exec.Command("bash", "-c",
			"ip netns exec vpn-hub-sb curl -s --max-time 5 https://1.1.1.1/cdn-cgi/trace | grep '^ip=' || true").Output()
		if strings.Contains(string(out), "ip=") {
			reached = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !reached {
		state, _ := exec.Command("bash", "-c",
			"systemctl status vpn-hub-proxy-sb.service --no-pager -l | tail -20; ip -n vpn-hub-sb addr; ip -n vpn-hub-sb rule; ip -n vpn-hub-sb route; systemctl status sisb-server.service --no-pager -l | tail -10").CombinedOutput()
		t.Fatalf("no traffic passed through the sing-box tunnel:\n%s", state)
	}
}
