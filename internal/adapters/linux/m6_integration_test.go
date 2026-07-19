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

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/adapters/linux"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

// corp is one stand-in private network: a WireGuard server with a name server and a
// service behind it, in a namespace of its own.
//
// Four of them, because the milestone's claim is not "a private network works" but
// "several do, at once, alongside the internet, by name". One would pass while the
// marks collided, the sets were shared, or the resolver answered from the wrong
// network.
type corp struct {
	id      string // corp-a
	set     string // internal_corp_a
	index   int    // 0..3
	zone    string // corpa.internal
	subnet  string // 10.20.0.0/24
	service string // 10.20.0.80
	// dynamic is deliberately outside the declared subnet, so nothing static routes
	// it. It is reachable only if dnsmasq put the answer into the network's set, which
	// is the whole mechanism split-DNS rests on.
	dynamic string // 10.60.0.80
	nameSrv string // 10.20.0.53
	linkNet string // 10.91.0.0/30 -- hub side of the veth to the stand-in
	tunNet  string // 10.71.0.0/24 -- inside the WireGuard tunnel
	public  string
}

func corps() []corp {
	var result []corp
	for index, letter := range []string{"a", "b", "c", "d"} {
		octet := 20 + index
		result = append(result, corp{
			id:      "corp-" + letter,
			set:     "internal_corp_" + letter,
			index:   index,
			zone:    fmt.Sprintf("corp%s.internal", letter),
			subnet:  fmt.Sprintf("10.%d.0.0/24", octet),
			service: fmt.Sprintf("10.%d.0.80", octet),
			dynamic: fmt.Sprintf("10.%d.0.80", 60+index),
			nameSrv: fmt.Sprintf("10.%d.0.53", octet),
			linkNet: fmt.Sprintf("10.9%d.0", index+1),
			tunNet:  fmt.Sprintf("10.7%d.0", index+1),
		})
	}
	return result
}

func (c corp) ns() string       { return "sicorp" + string(c.id[len(c.id)-1]) }
func (c corp) hostVeth() string { return "vsi" + string(c.id[len(c.id)-1]) }
func (c corp) peerVeth() string { return "vsp" + string(c.id[len(c.id)-1]) }
func (c corp) port() int        { return 52000 + c.index }

// build brings the stand-in up and returns the WireGuard configuration the hub needs
// to dial it, in the form a provider would hand over.
func (c *corp) build(t *testing.T, hubPublic string) string {
	t.Helper()
	t.Cleanup(func() {
		try("ip netns del %s", c.ns())
		try("ip link del %s", c.hostVeth())
	})

	key := sh(t, "wg genkey")
	c.public = sh(t, "echo %q | wg pubkey", key)

	sh(t, "ip netns add %s", c.ns())
	sh(t, "ip link add %s type veth peer name %s", c.hostVeth(), c.peerVeth())
	sh(t, "ip link set %s netns %s", c.peerVeth(), c.ns())
	sh(t, "ip addr add %s.1/30 dev %s && ip link set %s up", c.linkNet, c.hostVeth(), c.hostVeth())
	sh(t, "ip -n %s addr add %s.2/30 dev %s", c.ns(), c.linkNet, c.peerVeth())
	sh(t, "ip -n %s link set %s up && ip -n %s link set lo up", c.ns(), c.peerVeth(), c.ns())

	keyFile := filepath.Join(t.TempDir(), "corp.key")
	sh(t, "printf '%%s\\n' %q > %s && chmod 600 %s", key, keyFile, keyFile)
	// Created inside the namespace so its socket lives there and it can answer.
	sh(t, "ip netns exec %s ip link add wg0 type wireguard", c.ns())
	sh(t, "ip netns exec %s wg set wg0 private-key %s listen-port %d peer %q allowed-ips %s.2/32",
		c.ns(), keyFile, c.port(), hubPublic, c.tunNet)
	sh(t, "ip -n %s addr add %s.1/24 dev wg0 && ip -n %s link set wg0 up", c.ns(), c.tunNet, c.ns())

	// The private resources: a service and the name server that knows about it.
	sh(t, "ip -n %s addr add %s/32 dev lo", c.ns(), c.service)
	sh(t, "ip -n %s addr add %s/32 dev lo", c.ns(), c.dynamic)
	sh(t, "ip -n %s addr add %s/32 dev lo", c.ns(), c.nameSrv)
	sh(t, "ip netns exec %s sysctl -qw net.ipv4.ip_forward=1", c.ns())

	go func() {
		_ = exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s dnsmasq --keep-in-foreground --no-resolv --no-hosts "+
				"--bind-interfaces --listen-address=%s --address=/app.%s/%s --address=/dyn.%s/%s",
			c.ns(), c.nameSrv, c.zone, c.service, c.zone, c.dynamic)).Run()
	}()
	go func() {
		_ = exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s timeout 600 python3 -m http.server 80 --bind %s", c.ns(), c.service)).Run()
	}()
	go func() {
		_ = exec.Command("bash", "-c", fmt.Sprintf(
			"ip netns exec %s timeout 600 python3 -m http.server 80 --bind %s", c.ns(), c.dynamic)).Run()
	}()

	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s.2/32

[Peer]
PublicKey = %s
Endpoint = %s.2:%d
AllowedIPs = %s, %s, %s/32
PersistentKeepalive = 5
`, hubPrivateOf(t), c.tunNet, c.public, c.linkNet, c.port(), c.subnet, c.tunNet+".0/24", c.dynamic)
}

// hubPrivateOf keeps one key for the hub's side of every stand-in tunnel, which is
// what a single hub with several providers actually looks like.
var hubTunnelKey, hubTunnelPublic string

func hubPrivateOf(t *testing.T) string {
	t.Helper()
	if hubTunnelKey == "" {
		hubTunnelKey = sh(t, "wg genkey")
		hubTunnelPublic = sh(t, "echo %q | wg pubkey", hubTunnelKey)
	}
	return hubTunnelKey
}

// TestOneConnectionReachesEverything is the milestone the project exists for: a
// device connects once and gets the internet through its chosen egress and several
// private networks by name at the same time, with the hub deciding by destination.
//
// It drives the real reconciler -- the same compile, the same adapters, the same
// ordering the agent uses -- rather than assembling the path by hand, because most
// of what broke here historically was the ordering and the plan, not the rules.
func TestOneConnectionReachesEverything(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("this builds real namespaces and needs root")
	}
	for _, binary := range []string{"ip", "nft", "wg", "jq", "curl", "dnsmasq", "dig", "python3"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	uplink := sh(t, "ip -j route show default | jq -r '.[0].dev'")
	if uplink == "" || uplink == "null" {
		t.Skip("no default route on this machine")
	}

	const (
		ingress    = "awg0"
		clientNet  = "10.80.0"
		clientAddr = clientNet + ".2"
		hubDNS     = clientNet + ".1"
		hubPort    = 51820
	)
	cleanup := func() {
		try("systemctl stop vpn-hub-dns.service")
		try("systemctl stop vpn-hub-dns-upstream.service")
		try("ip netns del m6client")
		try("rm -rf /etc/netns/m6client")
		try("ip link del vm6")
		try("ip link del %s", ingress)
		try("nft delete table inet vpn_hub")
		for _, network := range corps() {
			// Every tunnel gets a SOCKS endpoint, private networks included, so each
			// leaves a unit and a table of its own behind.
			try("systemctl stop vpn-hub-socks-%s.service", network.id)
			try("nft delete table inet vpn_hub_socks_%s", strings.ReplaceAll(network.id, "-", "_"))
			try("ip netns del vpn-hub-%s", network.id)
			try("ip link del vh-%s", network.id)
		}
		out, _ := exec.Command("bash", "-c", "ip rule show | grep fwmark || true").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if fields := strings.Fields(line); len(fields) >= 6 {
				try("ip rule del fwmark %s lookup %s", fields[4], fields[6-1])
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	// The hub's own identity, and one key shared by its side of every stand-in.
	hubKey := sh(t, "wg genkey")
	hubPublic := sh(t, "echo %q | wg pubkey", hubKey)
	clientKey := sh(t, "wg genkey")
	clientPublic := sh(t, "echo %q | wg pubkey", clientKey)
	_ = hubPrivateOf(t)

	configDir := t.TempDir()
	runtimeDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(configDir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}

	networks := corps()
	var tunnels []domain.Tunnel
	for index := range networks {
		conf := networks[index].build(t, hubTunnelPublic)
		path := filepath.Join(configDir, "secrets", networks[index].id+".conf")
		if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, domain.Tunnel{
			ID:         networks[index].id,
			Type:       domain.TunnelWireGuard,
			Role:       domain.RolePrivateNetwork,
			Source:     domain.TunnelSource{Kind: domain.SourceConfig, Value: "secrets/" + networks[index].id + ".conf"},
			Routes:     []string{networks[index].subnet},
			DNSZones:   []string{networks[index].zone},
			DNSServers: []string{networks[index].nameSrv},
		})
	}

	keyPath := filepath.Join(runtimeDir, "server.key")
	if err := os.WriteFile(keyPath, []byte(hubKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	state := domain.DesiredState{
		Revision: "m6",
		Hub: domain.Hub{
			Endpoint:        fmt.Sprintf("127.0.0.1:%d", hubPort),
			ServerPublicKey: hubPublic,
			ClientCIDR:      clientNet + ".0/24",
			DNSAddress:      hubDNS,
		},
		Devices: []domain.DeployedDevice{{
			ID: "laptop", Address: clientAddr + "/32",
			PublicKey: clientPublic, Egress: domain.EgressDirect,
		}},
		Tunnels: tunnels,
	}

	reconciler := application.HostReconciler{
		Firewall:      linux.NFTables{RuntimeDir: runtimeDir},
		Ingress:       linux.Ingress{SecretsDir: runtimeDir, LinkType: "wireguard", Tool: "wg"},
		Egress:        linux.Egress{SecretsDir: runtimeDir, DirectNamespaces: true},
		DNS:           linux.Dnsmasq{ConfigDir: runtimeDir},
		TunnelConfigs: linux.TunnelConfigFiles{Dir: configDir, Secrets: configadapter.SOPSSecretStore{}},
		Host:          linux.NetConf{},
		ServerKey:     linux.ServerKeyFile{Path: keyPath},
	}
	if _, err := reconciler.Apply(context.Background(), state); err != nil {
		t.Fatalf("the reconciler could not converge: %v", err)
	}

	// The client, in its own namespace, with the single profile the milestone
	// promises: one peer, everything routed to the hub, no per-network choice.
	// A client's profile carries `DNS = <hub>`, so the namespace gets the same. Without
	// it the client falls back to the host's stub resolver, which does not exist inside
	// a namespace -- and every name fails for a reason that has nothing to do with the
	// hub.
	sh(t, "mkdir -p /etc/netns/m6client && printf 'nameserver %s\n' > /etc/netns/m6client/resolv.conf", hubDNS)
	sh(t, "ip netns add m6client")
	sh(t, "ip link add vm6 type veth peer name vm6c")
	sh(t, "ip link set vm6c netns m6client")
	sh(t, "ip addr add 10.99.0.1/30 dev vm6 && ip link set vm6 up")
	sh(t, "ip -n m6client addr add 10.99.0.2/30 dev vm6c")
	sh(t, "ip -n m6client link set vm6c up && ip -n m6client link set lo up")

	clientKeyFile := filepath.Join(t.TempDir(), "client.key")
	sh(t, "printf '%%s\\n' %q > %s && chmod 600 %s", clientKey, clientKeyFile, clientKeyFile)
	sh(t, "ip link add m6wg type wireguard && ip link set m6wg netns m6client")
	sh(t, "ip -n m6client addr add %s/32 dev m6wg", clientAddr)
	sh(t, "ip netns exec m6client wg set m6wg private-key %s peer %q endpoint 10.99.0.1:%d "+
		"allowed-ips 0.0.0.0/0 persistent-keepalive 5", clientKeyFile, hubPublic, hubPort)
	sh(t, "ip -n m6client link set m6wg up && ip -n m6client route add default dev m6wg")

	// The hub listens on 127.0.0.1 in the revision, so the client's packets arrive
	// over the veth: point the interface at the address the client can actually
	// reach. Everything else about the ingress is what the reconciler built.
	sh(t, "wg set %s listen-port %d", ingress, hubPort)

	inClient := func(format string, args ...any) string {
		out, _ := exec.Command("bash", "-c",
			"ip netns exec m6client "+fmt.Sprintf(format, args...)+" 2>&1").Output()
		return strings.TrimSpace(string(out))
	}

	// Give the tunnels a moment: four handshakes and a resolver have to settle.
	var ready bool
	for range 15 {
		if strings.Contains(inClient("curl -s --max-time 5 https://1.1.1.1/cdn-cgi/trace"), "ip=") {
			ready = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !ready {
		t.Fatalf("the client never reached the internet\n%s", m6Diagnosis(t, networks))
	}

	// Claim one: every private network answers by name, through its own resolver.
	for _, network := range networks {
		name := "app." + network.zone
		var resolved string
		for range 8 {
			resolved = inClient("dig +short +time=2 +tries=1 @%s %s", hubDNS, name)
			if strings.Contains(resolved, network.service) {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !strings.Contains(resolved, network.service) {
			t.Fatalf("%s resolved to %q, want %s\n%s", name, resolved, network.service,
				m6Diagnosis(t, networks))
		}

		// Claim two: an answer whose address no declared route covers still routes,
		// because dnsmasq put it into that network's set as it went past. Checking
		// this against an address inside the declared subnet would prove nothing --
		// the static route already covers it.
		dynamic := "dyn." + network.zone
		var learned string
		for range 8 {
			learned = inClient("dig +short +time=2 +tries=1 @%s %s", hubDNS, dynamic)
			if strings.Contains(learned, network.dynamic) {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !strings.Contains(learned, network.dynamic) {
			t.Fatalf("%s resolved to %q, want %s", dynamic, learned, network.dynamic)
		}
		elements := sh(t, "nft list set inet vpn_hub %s", network.set)
		if !strings.Contains(elements, network.dynamic) {
			t.Errorf("%s was resolved but never entered %s, so the packet that follows "+
				"would leave by the internet path:\n%s", network.dynamic, network.set, elements)
		}
		if code := inClient("curl -s --max-time 8 -o /dev/null -w '%%{http_code}' http://%s/", dynamic); code != "200" {
			t.Errorf("%s answered %q rather than 200: a learned address is not being routed",
				dynamic, code)
		}

		// Claim three: and it is actually reachable, by name, from the one connection.
		code := inClient("curl -s --max-time 8 -o /dev/null -w '%%{http_code}' http://%s/", name)
		if code != "200" {
			t.Fatalf("%s answered %q rather than 200\n%s", name, code, m6Diagnosis(t, networks))
		}
	}

	// Claim four: none of that cost the client its internet.
	if trace := inClient("curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace"); !strings.Contains(trace, "ip=") {
		t.Errorf("reaching the private networks cost the client its internet: %q", trace)
	}

	// Claim five: a private network that goes down takes only itself with it. Not
	// the internet, and not the other three -- which is the whole reason each gets
	// its own namespace, mark and table.
	down := networks[1]
	sh(t, "ip -n vpn-hub-%s link set wg0 down", down.id)
	if code := inClient("curl -s --max-time 6 -o /dev/null -w '%%{http_code}' http://app.%s/", down.zone); code == "200" {
		t.Errorf("a downed private network was still reachable, so something else is carrying it")
	}
	for _, network := range networks {
		if network.id == down.id {
			continue
		}
		code := inClient("curl -s --max-time 8 -o /dev/null -w '%%{http_code}' http://app.%s/", network.zone)
		if code != "200" {
			t.Errorf("%s stopped answering when %s went down: %q", network.zone, down.id, code)
		}
	}
	if trace := inClient("curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace"); !strings.Contains(trace, "ip=") {
		t.Errorf("a downed private network cost the client its internet")
	}
}

func m6Diagnosis(t *testing.T, networks []corp) string {
	t.Helper()
	steps := []struct{ title, command string }{
		{"hub interface", "wg show awg0"},
		{"client interface", "ip netns exec m6client wg show m6wg"},
		{"hub resolver", "systemctl status vpn-hub-dns.service --no-pager -l | tail -20"},
		{"resolver config", "cat /run/vpn-hub/dnsmasq-hub.conf 2>/dev/null || true"},
		{"ip rules", "ip rule show"},
		{"ruleset", "nft list table inet vpn_hub"},
	}
	for _, network := range networks {
		steps = append(steps, struct{ title, command string }{
			network.id + " tunnel",
			fmt.Sprintf("ip netns exec vpn-hub-%s wg show; ip -n vpn-hub-%s route", network.id, network.id),
		})
		// Which of the three it is: the service never started, the hub cannot reach
		// it, or only the client's path is broken.
		steps = append(steps, struct{ title, command string }{
			network.id + " service, from its own namespace",
			fmt.Sprintf("ip netns exec %s curl -s --max-time 4 -o /dev/null -w '%%{http_code}' http://%s/",
				network.ns(), network.service),
		})
		steps = append(steps, struct{ title, command string }{
			network.id + " service, from the hub",
			fmt.Sprintf("curl -s --max-time 4 -o /dev/null -w '%%{http_code}' http://%s/", network.service),
		})
	}
	var report strings.Builder
	for _, step := range steps {
		output, _ := exec.Command("bash", "-c", step.command+" 2>&1").CombinedOutput()
		fmt.Fprintf(&report, "\n--- %s ---\n%s", step.title, output)
	}
	return report.String()
}
