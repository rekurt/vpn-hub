//go:build integration

package linux_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	uuid, err := domain.RealityUserUUID(privateKey, "handshake-test")
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
			"systemctl status reality-server.service --no-pager -l | tail -30;"+
				"systemctl status reality-client.service --no-pager -l | tail -30").CombinedOutput()
		t.Fatalf("no traffic passed through the REALITY fallback:\n%s", state)
	}
}
