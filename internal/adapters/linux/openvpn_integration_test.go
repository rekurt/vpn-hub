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

// standInOpenVPN builds an OpenVPN server in a namespace and returns the .ovpn a
// client dials it with, in the server-push shape real providers ship: a CA, a client
// certificate signed by it, and the server pushing routes. That is the path the hub
// actually exercises -- it preserves the provider's file and lets the server push --
// so a lighter point-to-point config would test something the hub does not do.
func standInOpenVPN(t *testing.T, uplink string) string {
	t.Helper()
	const (
		ns   = "siovpn"
		veth = "vsiovpn"
		peer = "vspovpn"
		port = 51194
		net4 = "10.95.0"
	)
	t.Cleanup(func() {
		try("systemctl stop siovpn-server.service")
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
	// A minimal CA and two certificates. EC with `dh none`, which is how a 2.6 server
	// avoids the Diffie-Hellman parameter file older setups needed.
	sh(t, `cd %s
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout ca.key -out ca.crt -days 3 -nodes -subj /CN=vpnhub-test-ca >/dev/null 2>&1
for who in server client; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout $who.key -out $who.csr -nodes -subj /CN=$who >/dev/null 2>&1
  openssl x509 -req -in $who.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $who.crt -days 3 >/dev/null 2>&1
done`, dir)

	serverConf := filepath.Join(dir, "server.conf")
	sh(t, `cat > %s <<'EOF'
dev tun
proto udp
port %d
mode server
tls-server
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
ca %s/ca.crt
cert %s/server.crt
key %s/server.key
dh none
keepalive 5 30
verb 1
EOF`, serverConf, port, dir, dir, dir)

	// The server forwards its clients to the internet, and the host translates the
	// server's own veth out the uplink -- the same shape as the other stand-ins.
	sh(t, "ip netns exec %s sysctl -qw net.ipv4.ip_forward=1", ns)
	sh(t, "ip netns exec %s nft add table ip nat", ns)
	sh(t, "ip netns exec %s nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; }'", ns)
	sh(t, "ip netns exec %s nft add rule ip nat postrouting ip saddr 10.8.0.0/24 oifname %q masquerade", ns, peer)
	sh(t, "sysctl -qw net.ipv4.ip_forward=1")
	sh(t, "iptables -t nat -C POSTROUTING -s %s.0/30 -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s.0/30 -o %s -j MASQUERADE", net4, uplink, net4, uplink)

	sh(t, "systemd-run --quiet --collect --unit=siovpn-server ip netns exec %s openvpn --config %s", ns, serverConf)

	read := func(name string) string {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return strings.TrimSpace(string(content))
	}
	// The client file, exactly as a provider hands one over: inline CA and client
	// key material, a remote, and nothing that presumes the hub's environment.
	return fmt.Sprintf(`client
dev tun
proto udp
remote %s.2 %d
resolv-retry infinite
nobind
<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>
`, net4, port, read("ca.crt"), read("client.crt"), read("client.key"))
}

// TestOpenVPNEgressCarriesTraffic drives the real egress adapter against that server:
// the provider's client under systemd inside a namespace, its state read from the
// management socket, its tun device routed through. M9 was verified once on the lab
// against a provider since destroyed; this makes it repeatable.
func TestOpenVPNEgressCarriesTraffic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("builds real namespaces and needs root")
	}
	for _, binary := range []string{"ip", "openvpn", "openssl", "curl", "jq"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	uplink := sh(t, "ip -j route show default | jq -r '.[0].dev'")
	if uplink == "" || uplink == "null" {
		t.Skip("no default route")
	}

	cleanup := func() {
		try("systemctl stop vpn-hub-openvpn-ov.service")
		try("ip netns del vpn-hub-ov")
		try("ip link del vh-ov")
		try("ip rule del fwmark 0x101 lookup 100")
	}
	cleanup()
	t.Cleanup(cleanup)

	ovpn := standInOpenVPN(t, uplink)
	parsed, err := linux.ParseOpenVPNConfig(ovpn)
	if err != nil {
		t.Fatalf("the stand-in produced a config the hub cannot parse: %v", err)
	}

	egress := linux.Egress{SecretsDir: t.TempDir(), DirectNamespaces: true}
	spec := domain.EgressSpec{
		TunnelID: "ov", Namespace: "vpn-hub-ov",
		HostVeth: "vh-ov", PeerVeth: "uplink0",
		HostAddress: "10.90.0.1/30", PeerAddress: "10.90.0.2/30",
		Mark: 0x101, RouteTable: 100, ClientCIDR: "10.80.0.0/24",
		Interface: "ovpn0",
		Type:      domain.TunnelOpenVPN,
		OpenVPN:   parsed,
	}
	if err := egress.Apply(context.Background(), []domain.EgressSpec{spec}); err != nil {
		t.Fatalf("the OpenVPN egress did not come up: %v", err)
	}

	var reached bool
	for range 20 {
		out, _ := exec.Command("bash", "-c",
			"ip netns exec vpn-hub-ov curl -s --max-time 5 https://1.1.1.1/cdn-cgi/trace | grep '^ip=' || true").Output()
		if strings.Contains(string(out), "ip=") {
			reached = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !reached {
		state, _ := exec.Command("bash", "-c",
			"systemctl status vpn-hub-openvpn-ov.service --no-pager -l | tail -25; ip -n vpn-hub-ov addr; ip -n vpn-hub-ov route").CombinedOutput()
		t.Fatalf("no traffic passed through the OpenVPN tunnel:\n%s", state)
	}

	// The management socket the health check reads must report the tunnel up, not
	// merely that a process is running.
	socket := linux.OpenVPNManagementSocket(egress.SecretsDir, "ov")
	if st, err := linux.OpenVPNState(socket, 5*time.Second); err != nil {
		t.Errorf("management socket unreadable: %v", err)
	} else if st != "CONNECTED" {
		t.Errorf("management socket reports %q, want CONNECTED", st)
	}
}
