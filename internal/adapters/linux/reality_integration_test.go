//go:build integration

package linux_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/domain"
)

// TestRealityHandshakeCompletes is the question the whole fallback rests on: does
// this sing-box release complete a REALITY handshake against keys the hub itself
// generated?
//
// It was worth asking. REALITY had never handshaken on the lab, and the suspicion
// was the key encoding -- sing-box reads base64url, while the hub's ordinary
// X25519 helpers emit standard base64. A key in the wrong encoding still decodes
// to 32 bytes and still looks like a key, so nothing before this test could tell
// the two apart.
//
// Client and server are both sing-box on loopback: REALITY is userspace TCP, so no
// namespace, no root and no kernel module is involved. What is under test is the
// protocol and the key material, nothing about routing.
func TestRealityHandshakeCompletes(t *testing.T) {
	if _, err := exec.LookPath("sing-box"); err != nil {
		t.Skip("sing-box is not installed")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed")
	}

	// REALITY mimics a real TLS 1.3 site and hands unauthenticated connections to
	// it, so the server has to reach one. An unreachable network says nothing about
	// whether the hub works.
	const handshakeTarget = "www.cloudflare.com"
	if err := exec.Command("curl", "-sS", "--max-time", "10", "-o", "/dev/null",
		"https://"+handshakeTarget).Run(); err != nil {
		t.Skipf("%s is unreachable from here: %v", handshakeTarget, err)
	}

	privateKey, publicKey, err := domain.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, devicePublic, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := domain.RealityUserUUID(privateKey, "handshake-test", devicePublic)
	if err != nil {
		t.Fatal(err)
	}
	shortID := domain.RealityShortID(publicKey)

	const (
		serverPort = 18444
		socksPort  = 18445
	)
	dir := t.TempDir()

	server := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "vless", "listen": "127.0.0.1", "listen_port": serverPort,
			"users": []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{
				"enabled": true, "server_name": handshakeTarget,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": handshakeTarget, "server_port": 443},
					"private_key": privateKey,
					"short_id":    []any{shortID},
				},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}
	client := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "vless", "server": "127.0.0.1", "server_port": serverPort,
			"uuid": uuid, "flow": "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled": true, "server_name": handshakeTarget,
				"utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled": true, "public_key": publicKey, "short_id": shortID,
				},
			},
		}},
	}

	for name, config := range map[string]map[string]any{"server": server, "client": client} {
		encoded, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, role := range []string{"server", "client"} {
		unit := "reality-" + role
		try("systemctl stop %s.service", unit)
		t.Cleanup(func() { try("systemctl stop %s.service", unit) })
		sh(t, "systemd-run --quiet --collect --unit=%s sing-box run -c %s",
			unit, filepath.Join(dir, role+".json"))
	}

	var body string
	for range 15 {
		out, _ := exec.Command("bash", "-c", fmt.Sprintf(
			"curl -sS --max-time 8 --proxy socks5h://127.0.0.1:%d https://1.1.1.1/cdn-cgi/trace || true",
			socksPort)).Output()
		if strings.Contains(string(out), "ip=") {
			body = string(out)
			break
		}
		time.Sleep(2 * time.Second)
	}
	if body == "" {
		state, _ := exec.Command("bash", "-c",
			"journalctl -u reality-server --no-pager -n 40;"+
				"journalctl -u reality-client --no-pager -n 40").CombinedOutput()
		t.Fatalf("no traffic passed through the REALITY fallback:\n%s", state)
	}
}

// TestRealityIngressReportsAListenerThatCannotStart occupies the port and then
// asks the adapter to bring the listener up.
//
// It exists because the first attempt at this check passed its unit tests and
// did nothing here: it asked `systemctl is-active`, which answers a failed unit
// with the word on stdout and exit 3, and a non-zero exit is where the runner
// drops stdout. The empty string matched no state, so a listener that never
// started read as one still starting, and the reconcile reported success. Only a
// real systemd could tell the difference.
func TestRealityIngressReportsAListenerThatCannotStart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("binds a privileged port and needs root")
	}
	for _, binary := range []string{"sing-box", "systemd-run", "systemctl"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}

	occupied, err := net.Listen("tcp", fmt.Sprintf(":%d", domain.RealityPort))
	if err != nil {
		t.Skipf("port %d is not available to hold: %v", domain.RealityPort, err)
	}
	defer func() { _ = occupied.Close() }()

	runtimeDir, err := os.MkdirTemp("/run", "vpn-hub-reality")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })

	keyFile := linux.RealityKeyFile{Path: filepath.Join(t.TempDir(), "reality.key")}
	publicKey, err := keyFile.Create()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := keyFile.PrivateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ingress := linux.RealityIngress{SecretsDir: runtimeDir}
	t.Cleanup(func() { _ = ingress.Apply(context.Background(), domain.RealityIngressSpec{}) })

	err = ingress.Apply(context.Background(), domain.RealityIngressSpec{
		Enabled: true, Port: domain.RealityPort, ServerName: "www.cloudflare.com",
		PrivateKey: privateKey, ShortID: domain.RealityShortID(publicKey),
		DNSAddress: "10.80.0.1",
		Users: []domain.RealityUser{{
			DeviceID: "macbook", UUID: "3b1c8a52-4b6e-4d8a-9f00-0123456789ab",
		}},
	})
	if err == nil {
		t.Fatal("a listener that could not bind its port was reported as reconciled")
	}
	if !strings.Contains(err.Error(), "did not stay up") {
		t.Errorf("the failure was reported as something else: %v", err)
	}
}

// standInResolver runs dnsmasq on a private address and returns it, standing in
// for the hub's own resolver. Private on purpose: hub.client_cidr makes
// dns_address private on every real hub, and the listener refuses private
// destinations, so the address has to be private for the test to be about
// anything.
func standInResolver(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Skip("dnsmasq is not installed")
	}
	const address = "10.80.0.1"
	try("ip addr add %s/32 dev lo", address)
	try("systemctl stop reality-resolver.service")
	t.Cleanup(func() {
		try("systemctl stop reality-resolver.service")
		try("ip addr del %s/32 dev lo", address)
	})
	sh(t, "systemd-run --quiet --unit=reality-resolver dnsmasq --keep-in-foreground "+
		"--listen-address=%s --bind-interfaces --no-resolv --server=1.1.1.1", address)

	for range 20 {
		if exec.Command("dig", "+short", "+time=1", "+tries=1", "example.com", "@"+address).Run() == nil {
			return address
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Skip("the stand-in resolver did not come up")
	return ""
}

// assertUDPThroughProxy sends one DNS query over the proxy's SOCKS5 UDP
// association. curl cannot speak UDP through a proxy, so the association is done
// by hand: greeting, UDP ASSOCIATE, then a datagram with the SOCKS request header
// in front of the query.
func assertUDPThroughProxy(t *testing.T, socksPort int) {
	t.Helper()

	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 10*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	defer func() { _ = control.Close() }()
	if err := control.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greet the proxy: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil || greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("the proxy refused the greeting: %v %v", greeting, err)
	}

	// UDP ASSOCIATE with an unspecified address: the proxy answers with the relay
	// endpoint it wants the datagrams on.
	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("ask for a UDP association: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil {
		t.Fatalf("read the association reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("the proxy refused UDP: reply code %d", reply[1])
	}
	relayPort := int(reply[8])<<8 | int(reply[9])

	// A minimal DNS query for example.com A, prefixed with the SOCKS UDP header.
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	datagram := append([]byte{0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 53}, query...)

	relay, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", relayPort))
	if err != nil {
		t.Fatalf("dial the relay: %v", err)
	}
	defer func() { _ = relay.Close() }()
	if err := relay.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.Write(datagram); err != nil {
		t.Fatalf("send the query: %v", err)
	}
	answer := make([]byte, 4096)
	read, err := relay.Read(answer)
	if err != nil {
		state, _ := exec.Command("bash", "-c",
			"journalctl -u vpn-hub-reality --no-pager -n 40").CombinedOutput()
		t.Fatalf("no UDP answer came back through the fallback: %v\n%s", err, state)
	}
	// Past the SOCKS header, the DNS transaction id must be the one that was sent.
	if read < 14 || answer[10] != 0x12 || answer[11] != 0x34 {
		t.Fatalf("the UDP answer is not the reply to the query: %x", answer[:min(read, 32)])
	}
}

// TestRealityIngressCarriesTraffic drives the production path end to end: the
// adapter renders the listener's configuration and runs it as the transient unit
// the reconciler would, a device's link is issued exactly as the bot issues it,
// and a client built from that link carries traffic through it.
//
// The previous test answers "does REALITY work at all"; this one answers "do the
// two halves the hub generates agree with each other" -- the listener's user list
// and the link's credential are derived independently from the same key, so a
// mistake in either derivation shows up here and nowhere else.
func TestRealityIngressCarriesTraffic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runs a listener on a privileged port and needs root")
	}
	for _, binary := range []string{"sing-box", "curl", "systemd-run"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	const handshakeTarget = "www.cloudflare.com"
	if err := exec.Command("curl", "-sS", "--max-time", "10", "-o", "/dev/null",
		"https://"+handshakeTarget).Run(); err != nil {
		t.Skipf("%s is unreachable from here: %v", handshakeTarget, err)
	}

	// Under /run, not t.TempDir(): the listener's transient unit carries
	// PrivateTmp=true, so a configuration under /tmp exists for the test and not for
	// the process that has to read it. /run/vpn-hub is where it lives in production
	// for the same reason.
	runtimeDir, err := os.MkdirTemp("/run", "vpn-hub-reality")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })

	keyFile := linux.RealityKeyFile{Path: filepath.Join(t.TempDir(), "reality.key")}
	publicKey, err := keyFile.Create()
	if err != nil {
		t.Fatal(err)
	}
	_, devicePublic, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := keyFile.PrivateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := domain.RealityUserUUID(privateKey, "macbook", devicePublic)
	if err != nil {
		t.Fatal(err)
	}

	hub := domain.Hub{
		Endpoint:   "127.0.0.1:51820",
		DNSAddress: "10.80.0.1",
		Fallback: domain.IngressFallback{
			Reality: domain.RealityFallback{Enabled: true, ServerName: handshakeTarget},
		},
	}
	// A resolver at a private address, as on a real hub, where hub.client_cidr
	// makes dns_address private by construction. Pointing the listener at a public
	// resolver instead would leave the interesting question unasked: the listener
	// refuses private destinations, and whether that refusal also cuts off its own
	// lookups is exactly what a public resolver hides.
	resolver := standInResolver(t)
	spec := domain.RealityIngressSpec{
		Enabled: true, Port: domain.RealityPort, ServerName: handshakeTarget,
		PrivateKey: privateKey, ShortID: domain.RealityShortID(publicKey),
		DNSAddress: resolver,
		Users:      []domain.RealityUser{{DeviceID: "macbook", UUID: uuid}},
	}

	ingress := linux.RealityIngress{SecretsDir: runtimeDir}
	t.Cleanup(func() {
		_ = ingress.Apply(context.Background(), domain.RealityIngressSpec{})
	})
	if err := ingress.Apply(context.Background(), spec); err != nil {
		t.Fatalf("the listener did not come up: %v", err)
	}

	// Turning the fallback off has to close the port, so prove the unit is really
	// there before relying on the negative later.
	if err := exec.Command("systemctl", "is-active", "--quiet", "vpn-hub-reality.service").Run(); err != nil {
		state, _ := exec.Command("bash", "-c",
			"journalctl -u vpn-hub-reality --no-pager -n 40").CombinedOutput()
		t.Fatalf("the transient unit is not running:\n%s", state)
	}

	// The link a device receives, rendered by the same code the bot calls.
	link, err := runtimeadapter.RealityProfileRenderer{}.Link(hub, "macbook", uuid, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := linux.ParseVLESS(link)
	if err != nil {
		t.Fatalf("the issued link does not parse: %v", err)
	}

	const socksPort = 18446
	client := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "vless", "server": parsed.Server, "server_port": parsed.Port,
			"uuid": parsed.UUID, "flow": parsed.Flow,
			"tls": map[string]any{
				"enabled": true, "server_name": parsed.TLS.ServerName,
				"utls": map[string]any{"enabled": true, "fingerprint": parsed.TLS.Fingerprint},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": parsed.TLS.Reality.PublicKey,
					"short_id":   parsed.TLS.Reality.ShortID,
				},
			},
		}},
	}
	encoded, err := json.MarshalIndent(client, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(clientConfig, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	try("systemctl stop reality-device.service")
	t.Cleanup(func() { try("systemctl stop reality-device.service") })
	sh(t, "systemd-run --quiet --collect --unit=reality-device sing-box run -c %s", clientConfig)

	var body string
	for range 15 {
		out, _ := exec.Command("bash", "-c", fmt.Sprintf(
			"curl -sS --max-time 8 --proxy socks5h://127.0.0.1:%d https://1.1.1.1/cdn-cgi/trace || true",
			socksPort)).Output()
		if strings.Contains(string(out), "ip=") {
			body = string(out)
			break
		}
		time.Sleep(2 * time.Second)
	}
	if body == "" {
		state, _ := exec.Command("bash", "-c",
			"journalctl -u vpn-hub-reality --no-pager -n 40;"+
				"journalctl -u reality-device --no-pager -n 40").CombinedOutput()
		t.Fatalf("no traffic passed through the issued link:\n%s", state)
	}

	// A name, not an address. The listener resolves it itself, at the hub's own
	// resolver, on a private address the same configuration refuses as a
	// destination -- so this is the assertion that says the refusal cuts off
	// clients without cutting off the listener's own lookups. A probe by literal
	// address would pass either way and prove nothing about it.
	if out, err := exec.Command("bash", "-c", fmt.Sprintf(
		"curl -sS --max-time 10 --proxy socks5h://127.0.0.1:%d -o /dev/null -w '%%{http_code}' https://example.com/",
		socksPort)).Output(); err != nil || !strings.HasPrefix(string(out), "2") && !strings.HasPrefix(string(out), "3") {
		state, _ := exec.Command("bash", "-c",
			"journalctl -u vpn-hub-reality --no-pager -n 20;"+
				"journalctl -u reality-resolver --no-pager -n 10").CombinedOutput()
		t.Fatalf("a request by name did not pass (%q, %v):\n%s", out, err, state)
	}

	// UDP as well as TCP, and deliberately so: the `flow` setting the listener and
	// the link agree on is the sort of thing that carries TCP happily while
	// refusing every datagram, which would leave a device with no QUIC, no DNS over
	// UDP and no calls -- working enough to look fine and broken enough to matter.
	assertUDPThroughProxy(t, socksPort)

	// And the other half of the contract: switching the fallback off stops the
	// listener and removes the configuration that holds the key.
	if err := ingress.Apply(context.Background(), domain.RealityIngressSpec{}); err != nil {
		t.Fatalf("disabling the fallback failed: %v", err)
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "vpn-hub-reality.service").Run(); err == nil {
		t.Error("the listener is still running after the fallback was switched off")
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, linux.RealityConfigName)); !os.IsNotExist(err) {
		t.Errorf("the rendered configuration, which holds the key, was left behind (stat: %v)", err)
	}
}
