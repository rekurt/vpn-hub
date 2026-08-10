package linux

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func realitySpec() domain.RealityIngressSpec {
	return domain.RealityIngressSpec{
		Enabled:    true,
		Port:       domain.RealityPort,
		ServerName: "www.example.com",
		PrivateKey: "cGtxNTZKb0hRZHZKWXhpVGxDMFlpS3Y0dGRlbEVOSHU",
		ShortID:    "0123456789abcdef",
		DNSAddress: "10.80.0.1",
		Users: []domain.RealityUser{
			{DeviceID: "macbook", UUID: "3b1c8a52-4b6e-4d8a-9f00-0123456789ab", Mark: 0x101},
			{DeviceID: "phone", UUID: "7c2d9b63-5c7f-4e9b-8a11-1234567890bc"},
			{DeviceID: "tablet", UUID: "8d3eac74-6d80-4fac-9b22-234567890cde", Mark: 0x101},
		},
	}
}

func decodeReality(t *testing.T, spec domain.RealityIngressSpec) map[string]any {
	t.Helper()
	rendered, err := RenderRealityServerConfig(spec)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(rendered), &config); err != nil {
		t.Fatalf("the rendered configuration is not valid JSON: %v\n%s", err, rendered)
	}
	return config
}

func TestRenderRealityServerConfig(t *testing.T) {
	t.Parallel()
	config := decodeReality(t, realitySpec())

	inbound := config["inbounds"].([]any)[0].(map[string]any)
	if inbound["listen"] != "0.0.0.0" {
		t.Errorf("listen = %v; the host has no IPv6 path out", inbound["listen"])
	}
	if inbound["listen_port"].(float64) != float64(domain.RealityPort) {
		t.Errorf("listen_port = %v, want %d", inbound["listen_port"], domain.RealityPort)
	}

	reality := inbound["tls"].(map[string]any)["reality"].(map[string]any)
	if reality["private_key"] != realitySpec().PrivateKey {
		t.Error("the private key did not reach the configuration")
	}
	handshake := reality["handshake"].(map[string]any)
	if handshake["server"] != "www.example.com" || handshake["server_port"].(float64) != 443 {
		t.Errorf("handshake target = %v; unauthenticated connections must reach a real site", handshake)
	}

	// Every device is a user, and each carries the flow the server and client must
	// agree on -- a mismatch handshakes and then carries nothing.
	users := inbound["users"].([]any)
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3", len(users))
	}
	for _, entry := range users {
		user := entry.(map[string]any)
		if user["flow"] != "xtls-rprx-vision" {
			t.Errorf("user %v has no vision flow", user["name"])
		}
	}

	if servers := config["dns"].(map[string]any)["servers"].([]any); len(servers) != 1 ||
		servers[0].(map[string]any)["address"] != "10.80.0.1" {
		t.Errorf("dns servers = %v, want the hub resolver", servers)
	}
}

// Two devices sharing an egress share one outbound: a per-device outbound would
// only make the file longer and restart the listener whenever the device list is
// reshuffled.
func TestRealityOutboundsAreOnePerMark(t *testing.T) {
	t.Parallel()
	config := decodeReality(t, realitySpec())

	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 2 {
		t.Fatalf("got %d outbounds, want direct plus one marked: %v", len(outbounds), outbounds)
	}
	marks := map[string]any{}
	for _, entry := range outbounds {
		outbound := entry.(map[string]any)
		if outbound["domain_strategy"] != "ipv4_only" {
			t.Errorf("outbound %v may resolve to IPv6, which the host cannot reach", outbound["tag"])
		}
		marks[outbound["tag"].(string)] = outbound["routing_mark"]
	}
	if marks["direct"] != nil {
		t.Error("the default outbound carries a mark; unmarked is what leaves by the uplink")
	}

	route := config["route"].(map[string]any)
	if route["final"] != "direct" {
		t.Errorf("final = %v, want direct", route["final"])
	}
	rules := route["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want one per device with an egress: %v", len(rules), rules)
	}
	// The device with no mark must not appear: it belongs on the default outbound.
	if strings.Contains(mustJSON(t, rules), "phone") {
		t.Errorf("a device on direct got a route rule: %v", rules)
	}
}

func TestRenderRealityRefusesAnIncompleteSpec(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*domain.RealityIngressSpec){
		"no server name": func(s *domain.RealityIngressSpec) { s.ServerName = "" },
		"no private key": func(s *domain.RealityIngressSpec) { s.PrivateKey = "" },
		"no short id":    func(s *domain.RealityIngressSpec) { s.ShortID = "" },
		"no port":        func(s *domain.RealityIngressSpec) { s.Port = 0 },
		"a user with no credential": func(s *domain.RealityIngressSpec) {
			s.Users = []domain.RealityUser{{DeviceID: "macbook"}}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			spec := realitySpec()
			breakIt(&spec)
			if _, err := RenderRealityServerConfig(spec); err == nil {
				t.Fatal("an incomplete spec was rendered")
			}
		})
	}
}

func TestRealityIngressApply(t *testing.T) {
	t.Parallel()

	t.Run("enabled writes the config and starts the unit", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		host := &fakeHost{}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), realitySpec()); err != nil {
			t.Fatalf("apply: %v", err)
		}
		path := filepath.Join(dir, RealityConfigName)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		// The file holds the listener's private key and every device's credential.
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("config mode = %o, want 0600", got)
		}
		if !host.ran("systemd-run") || !host.ran("sing-box run -c "+path) {
			t.Errorf("the listener was not started; commands:\n%s", strings.Join(host.commands, "\n"))
		}
	})

	t.Run("an unchanged config leaves a running listener alone", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		rendered, err := RenderRealityServerConfig(realitySpec())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, RealityConfigName), []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
		host := &fakeHost{} // is-active succeeds
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), realitySpec()); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if host.ran("systemd-run") {
			t.Errorf("a healthy listener was restarted; commands:\n%s", strings.Join(host.commands, "\n"))
		}
	})

	// Turning the fallback off in configuration has to close the port, so a
	// disabled spec is an instruction rather than a no-op.
	t.Run("disabled stops the unit and removes the config", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, RealityConfigName)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		host := &fakeHost{}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), domain.RealityIngressSpec{}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !host.ran("systemctl stop vpn-hub-reality.service") {
			t.Error("the listener was left running")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("the configuration, which holds the key, was left behind (stat: %v)", err)
		}
	})
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
