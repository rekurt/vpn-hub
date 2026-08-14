package linux

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	if len(outbounds) != 3 {
		t.Fatalf("got %d outbounds, want direct, block and one marked: %v", len(outbounds), outbounds)
	}
	marks := map[string]any{}
	for _, entry := range outbounds {
		outbound := entry.(map[string]any)
		tag := outbound["tag"].(string)
		if tag != "block" && outbound["domain_strategy"] != "ipv4_only" {
			t.Errorf("outbound %v may resolve to IPv6, which the host cannot reach", tag)
		}
		marks[tag] = outbound["routing_mark"]
	}
	if marks["direct"] != nil {
		t.Error("the default outbound carries a mark; unmarked is what leaves by the uplink")
	}

	route := config["route"].(map[string]any)
	if route["final"] != "direct" {
		t.Errorf("final = %v, want direct", route["final"])
	}
	rules := route["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want the private-address refusal plus one per device with an egress: %v",
			len(rules), rules)
	}
	// The device with no mark must not appear: it belongs on the default outbound.
	if strings.Contains(mustJSON(t, rules), "phone") {
		t.Errorf("a device on direct got a route rule: %v", rules)
	}
}

// This path never passes through the forward chain, so none of the packet
// filter's client rules constrain it. Without an explicit refusal an
// authenticated device would reach the hub's own loopback services, the other
// clients' addresses and every private network the hub can see -- including the
// ones its allowed_devices deliberately exclude it from.
func TestRealityRefusesPrivateDestinations(t *testing.T) {
	t.Parallel()
	config := decodeReality(t, realitySpec())

	rules := config["route"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["ip_is_private"] != true || first["outbound"] != "block" {
		t.Fatalf("the first route rule does not refuse private destinations: %v", first)
	}

	blocked := false
	for _, entry := range config["outbounds"].([]any) {
		if outbound := entry.(map[string]any); outbound["tag"] == "block" && outbound["type"] == "block" {
			blocked = true
		}
	}
	if !blocked {
		t.Error("the refusal names an outbound that does not exist")
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

// realitySubState is how the adapter asks systemd what the listener is doing.
var realitySubState = "systemctl show " + realityUnit + ".service --property=SubState --value"

// A failure to ask is not an answer. `is-active` reports "not active" and "I
// could not tell you" with the same non-zero exit, and reading the second as the
// first would have Observe report an absence it never established -- and a hub
// with the fallback switched off look converged while a listener stayed up.
func TestAppliedReportsAFailureToObserve(t *testing.T) {
	t.Parallel()
	host := &fakeHost{failures: map[string]error{
		realitySubState: errors.New("Failed to connect to bus: No such file or directory"),
	}}
	ingress := RealityIngress{Run: host.run, SecretsDir: t.TempDir()}

	if _, err := ingress.Applied(context.Background()); err == nil {
		t.Fatal("a listener whose state could not be read was reported as absent")
	}
}

// A listener that is up but carries no record of what it was started from is not
// the same as no listener. With the fallback switched off the two would agree,
// and a live TCP/443 listener would be reported as converged.
func TestAppliedSeparatesAnUnknownListenerFromNone(t *testing.T) {
	t.Parallel()

	running := &fakeHost{replies: map[string]string{realitySubState: "running\n"}}
	applied, err := RealityIngress{Run: running.run, SecretsDir: t.TempDir()}.
		Applied(context.Background())
	if err != nil {
		t.Fatalf("applied: %v", err)
	}
	if applied != RealityRunningUnknown {
		t.Errorf("applied = %q, want %q", applied, RealityRunningUnknown)
	}

	// A unit waiting out RestartSec, or still coming up, is present: systemd will
	// have a listener on 443 either way, and a hub that no longer wants one has to
	// see that rather than agree with itself while the port stays open.
	for _, substate := range []string{"auto-restart", "start", "stop-sigterm"} {
		host := &fakeHost{replies: map[string]string{realitySubState: substate + "\n"}}
		applied, err := RealityIngress{Run: host.run, SecretsDir: t.TempDir()}.
			Applied(context.Background())
		if err != nil {
			t.Fatalf("applied(%s): %v", substate, err)
		}
		if applied != RealityRunningUnknown {
			t.Errorf("applied(%s) = %q, want %q", substate, applied, RealityRunningUnknown)
		}
	}

	for _, substate := range []string{"dead", "failed"} {
		host := &fakeHost{replies: map[string]string{realitySubState: substate + "\n"}}
		applied, err := RealityIngress{Run: host.run, SecretsDir: t.TempDir()}.
			Applied(context.Background())
		if err != nil {
			t.Fatalf("applied(%s): %v", substate, err)
		}
		if applied != "" {
			t.Errorf("applied(%s) = %q, want empty: nothing is there", substate, applied)
		}
	}
}

// writeAppliedReality puts a runtime directory in the state a successful pass
// leaves behind: the rendered configuration, and the fingerprint recording that
// the running listener was started from it.
func writeAppliedReality(t *testing.T, dir string, spec domain.RealityIngressSpec) {
	t.Helper()
	rendered, err := RenderRealityServerConfig(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, RealityConfigName), []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(rendered)))
	if err := os.WriteFile(filepath.Join(dir, RealityConfigName+".applied"), []byte(fingerprint), 0o600); err != nil {
		t.Fatal(err)
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
		// Checked before starting: systemd-run answers "the job was accepted", not
		// "the process survived", so a configuration this release rejects would
		// otherwise become a unit that restarts forever with every pass reporting fine.
		if !host.ran("sing-box check -c " + path) {
			t.Errorf("the configuration was not checked before starting it:\n%s", strings.Join(host.commands, "\n"))
		}
	})

	// A stop that did not work means the listener may still be accepting on 443.
	// Removing its configuration and reporting success would leave the operator
	// believing the port is shut, and every reconcile would repeat the belief.
	t.Run("a stop that fails is reported, and the config is kept", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, RealityConfigName)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		host := &fakeHost{failures: map[string]error{
			"systemctl stop " + realityUnit + ".service": fmt.Errorf("Failed to stop: Connection timed out"),
		}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		err := ingress.Apply(context.Background(), domain.RealityIngressSpec{})
		if err == nil || !strings.Contains(err.Error(), "stop the listener") {
			t.Fatalf("err = %v, want the failed stop reported", err)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Error("the configuration was removed although the listener may still be running")
		}
	})

	// The ordinary state of a hub that never turned the fallback on: systemd
	// answers exit 5 and says the unit is not loaded, which is not a failure.
	t.Run("stopping a unit that was never there is not a failure", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		// systemd's own wording, kept verbatim: recognising it is the whole point.
		notLoaded := fmt.Sprintf(
			"systemctl stop %s.service: exit status 5: Failed to stop %s.service: Unit %s.service not loaded.",
			realityUnit, realityUnit, realityUnit)
		host := &fakeHost{failures: map[string]error{
			"systemctl stop " + realityUnit + ".service": errors.New(notLoaded),
		}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), domain.RealityIngressSpec{}); err != nil {
			t.Fatalf("apply: %v", err)
		}
	})

	// The user list lives in the running process, so replacing it is how a revoked
	// device stops being admitted. A stop that quietly failed would leave the old
	// process serving the old list while the pass reported the revision applied.
	t.Run("a stop that fails on the update path is reported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		host := &fakeHost{failures: map[string]error{
			"systemctl stop " + realityUnit + ".service": errors.New("Failed to stop: Connection timed out"),
		}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		err := ingress.Apply(context.Background(), realitySpec())
		if err == nil || !strings.Contains(err.Error(), "stop the listener") {
			t.Fatalf("err = %v, want the failed stop reported", err)
		}
		if host.ran("systemd-run") {
			t.Error("a replacement was started although the old listener may still be running")
		}
	})

	t.Run("a rejected configuration is reported, not started", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, RealityConfigName)
		host := &fakeHost{failures: map[string]error{
			"sing-box check -c " + path: fmt.Errorf("exit status 1"),
		}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		err := ingress.Apply(context.Background(), realitySpec())
		if err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("err = %v, want the rejection reported", err)
		}
		if host.ran("systemd-run") {
			t.Error("a configuration known to be bad was started anyway")
		}
	})

	// A port already in use, a missing binary, capabilities the kernel refuses:
	// each leaves a unit that dies right after systemd-run reports success. The
	// fallback is not part of Observe, so nothing else would ever notice.
	t.Run("a listener that dies on startup is reported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		host := &fakeHost{replies: map[string]string{
			"systemctl show " + realityUnit + ".service --property=SubState --value": "auto-restart\n",
			"journalctl -u " + realityUnit + " --no-pager -n 10":                     "address already in use",
		}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		err := ingress.Apply(context.Background(), realitySpec())
		if err == nil {
			t.Fatal("a dead listener was reported as a success")
		}
		if !strings.Contains(err.Error(), "address already in use") {
			t.Errorf("the journal did not reach the operator: %v", err)
		}
	})

	t.Run("a listener that comes up is not reported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		host := &fakeHost{replies: map[string]string{
			"systemctl show " + realityUnit + ".service --property=SubState --value": "running\n",
		}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), realitySpec()); err != nil {
			t.Fatalf("apply: %v", err)
		}
	})

	t.Run("an unchanged config leaves a running listener alone", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeAppliedReality(t, dir, realitySpec())
		host := &fakeHost{replies: map[string]string{realitySubState: "running\n"}}
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), realitySpec()); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if host.ran("systemd-run") {
			t.Errorf("a healthy listener was restarted; commands:\n%s", strings.Join(host.commands, "\n"))
		}
	})

	// A written configuration is not an applied one. The file has to be on disk
	// before the unit can start from it, so a pass that wrote it and then failed to
	// replace the process leaves the new bytes beside the old listener -- still
	// serving the user list it started with, a revoked device included. Reading the
	// file back would call that done and never retry.
	t.Run("a config written but never started is retried", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		rendered, err := RenderRealityServerConfig(realitySpec())
		if err != nil {
			t.Fatal(err)
		}
		// Written, but no record of a replacement that worked.
		if err := os.WriteFile(filepath.Join(dir, RealityConfigName), []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
		host := &fakeHost{} // is-active succeeds: the *old* listener is still up
		ingress := RealityIngress{Run: host.run, SecretsDir: dir}

		if err := ingress.Apply(context.Background(), realitySpec()); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !host.ran("systemd-run") {
			t.Errorf("the listener was not replaced, so the old user list stands:\n%s",
				strings.Join(host.commands, "\n"))
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
