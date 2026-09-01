package linux

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

func openVPNSpec() domain.EgressSpec {
	return domain.EgressSpec{
		TunnelID:    "corp",
		Namespace:   "vpn-hub-corp",
		HostVeth:    "vh-corp",
		PeerVeth:    "uplink0",
		HostAddress: "10.90.0.1/30",
		PeerAddress: "10.90.0.2/30",
		ClientCIDR:  "10.80.0.0/24",
		Interface:   "tun0",
		Type:        domain.TunnelOpenVPN,
		OpenVPN: domain.OpenVPNTunnel{
			// An IP-literal remote so ensureRemoteRoutes never touches the network.
			Remotes: []domain.OpenVPNRemote{{Host: "192.0.2.9", Port: 1194, Protocol: "udp"}},
			Config:  "client\nremote 192.0.2.9 1194 udp\n",
		},
	}
}

// prewriteOpenVPNConfig makes writeIfChanged report the configuration unchanged, so
// a test exercises the is-the-process-healthy path rather than the rewrite path.
func prewriteOpenVPNConfig(t *testing.T, dir string, spec domain.EgressSpec) {
	t.Helper()
	socket := OpenVPNManagementSocket(dir, spec.TunnelID)
	rendered := RenderOpenVPNConfig(spec.OpenVPN, spec.Interface, socket)
	if err := os.WriteFile(filepath.Join(dir, spec.TunnelID+"-openvpn.conf"), []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRenderOpenVPNConfig(t *testing.T) {
	t.Parallel()
	// No trailing newline on purpose: the renderer must supply one before appending.
	tunnel := domain.OpenVPNTunnel{Config: "client\nremote 192.0.2.9 1194 udp"}
	rendered := RenderOpenVPNConfig(tunnel, "tun0", "/run/vpn-hub/corp-openvpn.sock")

	if !strings.HasPrefix(rendered, "client\nremote 192.0.2.9 1194 udp\n") {
		t.Errorf("the provider's text was not preserved verbatim:\n%s", rendered)
	}
	for _, line := range []string{
		"\ndev tun0\n",
		"\ndev-type tun\n",
		"\nnobind\n",
		"\nmanagement /run/vpn-hub/corp-openvpn.sock unix\n",
		"\nscript-security 0\n",
	} {
		if !strings.Contains(rendered, line) {
			t.Errorf("rendered config is missing %q:\n%s", strings.TrimSpace(line), rendered)
		}
	}
}

// Regression for 15b4cc8: the unit can report active while the management socket is
// gone -- a /run wipe, or a process that stopped serving it. is-active alone then
// leaves the health check saying "socket not answering" forever, because
// convergence sees an unchanged config and an active unit and repairs nothing.
func TestEnsureOpenVPNRestartsWhenTheSocketIsDead(t *testing.T) {
	t.Parallel()

	t.Run("missing socket restarts the process", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		spec := openVPNSpec()
		prewriteOpenVPNConfig(t, dir, spec)
		host := &fakeHost{} // is-active succeeds; no socket file exists
		egress := Egress{Run: host.run, SecretsDir: dir}

		if err := egress.ensureOpenVPN(context.Background(), spec); err != nil {
			t.Fatalf("ensureOpenVPN: %v", err)
		}
		if !host.ran("systemctl stop vpn-hub-openvpn-corp.service") {
			t.Error("the stale unit was not stopped")
		}
		if !host.ran("systemd-run") || !host.ran("openvpn --config") {
			t.Errorf("the process was not restarted; commands:\n%s", strings.Join(host.commands, "\n"))
		}
	})

	t.Run("live socket leaves the process alone", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		spec := openVPNSpec()
		prewriteOpenVPNConfig(t, dir, spec)
		if err := os.WriteFile(OpenVPNManagementSocket(dir, spec.TunnelID), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		host := &fakeHost{}
		egress := Egress{Run: host.run, SecretsDir: dir}

		if err := egress.ensureOpenVPN(context.Background(), spec); err != nil {
			t.Fatalf("ensureOpenVPN: %v", err)
		}
		if host.ran("systemd-run") {
			t.Errorf("a healthy process was restarted; commands:\n%s", strings.Join(host.commands, "\n"))
		}
	})
}

// Regression for 99c6bb4: OpenVPN removes routes it installed when it reconnects,
// so the provider's address must be pinned to the veth on every reconcile -- not
// only when the generated configuration changes. Otherwise the next UDP handshake
// follows the tunnel that is currently down and can never recover.
func TestEnsureOpenVPNPinsRemoteRoutesEveryPass(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	spec := openVPNSpec()
	prewriteOpenVPNConfig(t, dir, spec)
	if err := os.WriteFile(OpenVPNManagementSocket(dir, spec.TunnelID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &fakeHost{}
	egress := Egress{Run: host.run, SecretsDir: dir}

	if err := egress.ensureOpenVPN(context.Background(), spec); err != nil {
		t.Fatalf("ensureOpenVPN: %v", err)
	}
	want := "ip -n vpn-hub-corp route replace 192.0.2.9/32 via 10.90.0.1 dev uplink0"
	if !host.ran(want) {
		t.Errorf("the provider route was not pinned; commands:\n%s", strings.Join(host.commands, "\n"))
	}
}

// Regression for 99af97b: on connect OpenVPN sends a greeting banner before
// anything is asked of it, so a single read can return the banner alone -- which
// parses as "no state" while the tunnel is perfectly up.
func TestOpenVPNStateReadsPastTheBanner(t *testing.T) {
	t.Parallel()
	// A hand-made short directory: t.TempDir() embeds the test name and can push a
	// unix socket path past the platform limit (104 bytes on darwin).
	dir, err := os.MkdirTemp("", "ovpn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		// The banner is unprompted -- OpenVPN greets on connect, before it is asked
		// anything -- so it goes out ahead of the caller's command.
		_, _ = connection.Write([]byte(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"))

		// Wait for that command before going further. The deferred close above would
		// otherwise race the caller's own "state\n", and writing to a unix socket whose
		// peer has already closed fails with EPIPE -- the caller then reports an error
		// instead of reading the reply queued up for it. The read is a synchronisation
		// point, not a gate: the reply goes out however it turns out, and the deadline
		// keeps a caller that connects and then says nothing from parking this
		// goroutine for the rest of the run.
		_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = connection.Read(make([]byte, 64))

		// The state line has to arrive in a read of its own. Landing together with the
		// banner it would parse out of a single read, and the accumulate loop this test
		// exists to cover would never be exercised.
		time.Sleep(30 * time.Millisecond)
		_, _ = connection.Write([]byte("1699999999,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,\r\nEND\r\n"))
	}()

	state, err := OpenVPNState(socket, 2*time.Second)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if state != "CONNECTED" {
		t.Fatalf("state = %q, want CONNECTED", state)
	}
}

func TestOpenVPNStateNamesAnUnansweringSocket(t *testing.T) {
	t.Parallel()
	_, err := OpenVPNState(filepath.Join(t.TempDir(), "missing.sock"), 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatalf("err = %v, want the not-answering diagnosis", err)
	}
}
