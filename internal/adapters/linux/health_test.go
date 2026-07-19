package linux

import (
	"context"
	"fmt"
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
