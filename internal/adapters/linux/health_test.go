package linux

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

// frozen is the moment every case is judged against.
var frozen = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

// dumpWithHandshake builds `wg show dump` output for a peer that last handshook at
// the given time; the zero time means never.
func dumpWithHandshake(at time.Time) string {
	stamp := "0"
	if !at.IsZero() {
		stamp = fmt.Sprintf("%d", at.Unix())
	}
	return "privkey\tpubkey\t51820\toff\n" +
		"peerkey\t(none)\tprovider:51820\t0.0.0.0/0\t" + stamp + "\t1024\t2048\toff\n"
}

func checker(host *fakeHost) HealthChecker {
	return HealthChecker{Run: host.run, Now: func() time.Time { return frozen }}
}

const dumpCommand = "ip netns exec vpn-hub-corp wg show wg0 dump"

func TestHealthFromHandshake(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		handshake time.Time
		want      domain.HealthStatus
		reason    string
	}{
		"a recent handshake means traffic was flowing": {
			frozen.Add(-30 * time.Second), domain.HealthHealthy, "handshake",
		},
		// An idle tunnel looks exactly like this, so it is not evidence of failure.
		"a stale handshake is not proof of failure": {
			frozen.Add(-30 * time.Minute), domain.HealthUnknown, "only expected while idle",
		},
		"a tunnel that never handshook is down": {
			time.Time{}, domain.HealthUnhealthy, "never completed a handshake",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			host := &fakeHost{replies: map[string]string{dumpCommand: dumpWithHandshake(test.handshake)}}
			health, err := checker(host).Check(context.Background(), domain.Tunnel{ID: "corp"})
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if health.Status != test.want {
				t.Fatalf("Status = %q (%s), want %q", health.Status, health.Reason, test.want)
			}
			if !strings.Contains(health.Reason, test.reason) {
				t.Errorf("Reason = %q, want it to mention %q", health.Reason, test.reason)
			}
		})
	}
}

func TestMissingTunnelIsUnhealthy(t *testing.T) {
	t.Parallel()
	host := &fakeHost{failures: map[string]error{dumpCommand: fmt.Errorf("no such namespace")}}
	health, err := checker(host).Check(context.Background(), domain.Tunnel{ID: "corp"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthUnhealthy {
		t.Fatalf("Status = %q, want unhealthy", health.Status)
	}
}

// Probing from the host would measure the host's connectivity, which is exactly the
// path the tunnel exists to avoid: it would call a dead tunnel healthy.
func TestProbesRunInsideTheTunnelNamespace(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{dumpCommand: dumpWithHandshake(frozen.Add(-time.Minute))}}
	tunnel := domain.Tunnel{ID: "corp", Health: domain.HealthCheck{
		HTTPSURL: "https://example.test/", DNSName: "example.test",
	}}

	if _, err := checker(host).Check(context.Background(), tunnel); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, fragment := range []string{
		"ip netns exec vpn-hub-corp curl", "ip netns exec vpn-hub-corp timeout",
	} {
		if !host.ran(fragment) {
			t.Errorf("expected a probe run as %q; commands: %v", fragment, host.commands)
		}
	}
}

// A fresh handshake says the tunnel was working recently; a failing probe says it is
// not working now, and now wins.
func TestAFailingProbeOverridesAFreshHandshake(t *testing.T) {
	t.Parallel()
	host := &fakeHost{
		replies:  map[string]string{dumpCommand: dumpWithHandshake(frozen.Add(-10 * time.Second))},
		failures: map[string]error{},
	}
	tunnel := domain.Tunnel{ID: "corp", Health: domain.HealthCheck{HTTPSURL: "https://example.test/"}}
	host.failures["ip netns exec vpn-hub-corp curl -sS --max-time 5 -o /dev/null https://example.test/"] =
		fmt.Errorf("connection timed out")

	health, err := checker(host).Check(context.Background(), tunnel)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthUnhealthy {
		t.Fatalf("Status = %q (%s), want unhealthy", health.Status, health.Reason)
	}
	if !strings.Contains(health.Reason, "through the tunnel") {
		t.Errorf("Reason = %q, want it to say the probe went through the tunnel", health.Reason)
	}
}

// A passing probe is stronger evidence than an old handshake.
func TestAPassingProbeRescuesAStaleHandshake(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{dumpCommand: dumpWithHandshake(frozen.Add(-time.Hour))}}
	tunnel := domain.Tunnel{ID: "corp", Health: domain.HealthCheck{HTTPSURL: "https://example.test/"}}

	health, err := checker(host).Check(context.Background(), tunnel)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthHealthy {
		t.Fatalf("Status = %q (%s), want healthy", health.Status, health.Reason)
	}
}

// The adapter is the last place that could still run the value, so it refuses
// rather than trusting that validation happened earlier. A revision on disk may
// predate the rule that would have rejected it.
func TestAnUnsafeProbeTargetIsRefusedNotRun(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{dumpCommand: dumpWithHandshake(frozen.Add(-time.Minute))}}
	tunnel := domain.Tunnel{ID: "corp", Health: domain.HealthCheck{TCPAddress: "[; id ;]:443"}}

	health, err := checker(host).Check(context.Background(), tunnel)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, command := range host.commands {
		if strings.Contains(command, "id") && strings.Contains(command, "netns exec") {
			t.Fatalf("the payload reached a command: %q", command)
		}
	}
	if health.Status != domain.HealthUnhealthy {
		t.Errorf("Status = %s, want unhealthy: a probe that cannot be run has not passed", health.Status)
	}
}

// No shell is involved any more, so no shell can be talked into anything.
func TestTheTCPProbeUsesNoShell(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{dumpCommand: dumpWithHandshake(frozen.Add(-time.Minute))}}
	tunnel := domain.Tunnel{ID: "corp", Health: domain.HealthCheck{TCPAddress: "10.20.0.53:53"}}

	if _, err := checker(host).Check(context.Background(), tunnel); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, command := range host.commands {
		if strings.Contains(command, "bash") || strings.Contains(command, "sh -c") {
			t.Fatalf("a shell was used to open a socket: %q", command)
		}
	}
	if !host.ran("ip netns exec vpn-hub-corp curl") {
		t.Fatalf("the probe did not run; commands: %v", host.commands)
	}
}

// Both of these branches could be replaced by an unconditional "healthy" with the
// suite still green, which for a health check is the failure that matters most.
func TestAProxyWithNoProcessIsUnhealthy(t *testing.T) {
	t.Parallel()
	host := &fakeHost{failures: map[string]error{
		"systemctl is-active --quiet vpn-hub-proxy-corp.service": errNotRunning,
	}}
	tunnel := domain.Tunnel{ID: "corp", Type: domain.TunnelXray}

	health, err := checker(host).Check(context.Background(), tunnel)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthUnhealthy {
		t.Errorf("Status = %s, want unhealthy: the proxy is not running", health.Status)
	}
}

// A running process is not evidence that traffic passes, so with no probe the
// honest answer is that nothing was measured.
func TestARunningProxyWithNoProbeIsUnknown(t *testing.T) {
	t.Parallel()
	tunnel := domain.Tunnel{ID: "corp", Type: domain.TunnelXray}

	health, err := checker(&fakeHost{}).Check(context.Background(), tunnel)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthUnknown {
		t.Errorf("Status = %s, want unknown: nothing was measured", health.Status)
	}
}

// OpenVPN used to answer this same situation with "healthy", on the strength of its
// management channel alone. CONNECTED describes the control channel, which stays up
// through plenty of failures that stop data passing.
func TestConnectedWithoutAProbeIsUnknownNotHealthy(t *testing.T) {
	t.Parallel()
	// A unix socket path is limited to about a hundred characters, and the usual
	// temp directory name for a test this long already exceeds it.
	runtimeDir, err := os.MkdirTemp("", "vh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	openvpnStub(t, OpenVPNManagementSocket(runtimeDir, "corp"),
		">INFO:OpenVPN Management Interface\r\n1700000000,CONNECTED,SUCCESS,10.8.0.2,,\r\nEND\r\n")

	checker := HealthChecker{Run: (&fakeHost{}).run, RuntimeDir: runtimeDir, Now: func() time.Time { return frozen }}
	health, err := checker.Check(context.Background(), domain.Tunnel{ID: "corp", Type: domain.TunnelOpenVPN})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status == domain.HealthHealthy {
		t.Errorf("Status = healthy on the control channel alone; reason: %s", health.Reason)
	}
	if health.Status != domain.HealthUnknown {
		t.Errorf("Status = %s, want unknown", health.Status)
	}
}

// openvpnStub answers one connection on a management socket with a canned reply, so
// the OpenVPN health path can be exercised without OpenVPN.
func openvpnStub(t *testing.T, path, reply string) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = connection.Write([]byte(reply))
			_ = connection.Close()
		}
	}()
}
