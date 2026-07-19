package linux

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"vpn-hub/internal/domain"
)

// HandshakeGrace is how long a handshake stays convincing.
//
// WireGuard rekeys about every two minutes while traffic flows, so a handshake
// younger than this means the tunnel was carrying traffic very recently. An older
// one is not evidence of failure -- an idle tunnel legitimately has one -- which is
// why a stale handshake alone yields "unknown" rather than "unhealthy".
const HandshakeGrace = 3 * time.Minute

// HealthChecker judges an egress tunnel from inside its own namespace.
//
// Probing from the host would measure the host's connectivity, which is exactly the
// path the tunnel is meant to avoid: it would report healthy for a tunnel that is
// down, as long as the machine itself had internet.
type HealthChecker struct {
	Run runner
	Now func() time.Time
	// Timeout bounds each probe.
	Timeout time.Duration
}

func (h HealthChecker) run(ctx context.Context, name string, args ...string) (string, error) {
	if h.Run != nil {
		return h.Run(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

func (h HealthChecker) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h HealthChecker) timeout() time.Duration {
	if h.Timeout != 0 {
		return h.Timeout
	}
	return 5 * time.Second
}

func (h HealthChecker) Check(ctx context.Context, tunnel domain.Tunnel) (domain.TunnelHealth, error) {
	health := domain.TunnelHealth{
		TunnelID:  tunnel.ID,
		CheckedAt: h.now().UTC(),
		Status:    domain.HealthUnknown,
	}
	namespace := "vpn-hub-" + tunnel.ID

	output, err := h.run(ctx, "ip", "netns", "exec", namespace, "wg", "show", "wg0", "dump")
	if err != nil {
		health.Status = domain.HealthUnhealthy
		health.Reason = "the tunnel namespace or its interface does not exist"
		return health, nil
	}
	observed, err := ParseDump(output)
	if err != nil {
		return health, fmt.Errorf("read tunnel state: %w", err)
	}
	if len(observed.Peers) == 0 {
		health.Status = domain.HealthUnhealthy
		health.Reason = "the tunnel has no configured peer"
		return health, nil
	}

	peer := observed.Peers[0]
	switch {
	case peer.LatestHandshake.IsZero():
		health.Status = domain.HealthUnhealthy
		health.Reason = "the tunnel has never completed a handshake"
	case h.now().Sub(peer.LatestHandshake) <= HandshakeGrace:
		health.Status = domain.HealthHealthy
		health.Reason = fmt.Sprintf("handshake %s ago", h.now().Sub(peer.LatestHandshake).Round(time.Second))
	default:
		// Not a failure by itself: an idle tunnel looks exactly like this.
		health.Reason = fmt.Sprintf("last handshake was %s ago, which is only expected while idle",
			h.now().Sub(peer.LatestHandshake).Round(time.Second))
	}

	// Configured probes are authoritative: they are the only thing that establishes
	// the tunnel carries traffic right now, rather than that it did recently.
	reasons, ran := h.probe(ctx, namespace, tunnel.Health)
	if ran == 0 {
		return health, nil
	}
	if len(reasons) > 0 {
		health.Status = domain.HealthUnhealthy
		health.Reason = strings.Join(reasons, "; ")
		return health, nil
	}
	health.Status = domain.HealthHealthy
	health.Reason = fmt.Sprintf("%d probe(s) succeeded inside the tunnel", ran)
	return health, nil
}

// probe runs each configured check inside the namespace and returns the failures.
func (h HealthChecker) probe(ctx context.Context, namespace string, checks domain.HealthCheck) (reasons []string, ran int) {
	seconds := fmt.Sprintf("%d", int(h.timeout().Seconds()))

	if checks.TCPAddress != "" {
		ran++
		host, port, err := net.SplitHostPort(checks.TCPAddress)
		if err != nil {
			reasons = append(reasons, "tcp probe: "+err.Error())
		} else if _, err := h.run(ctx, "ip", "netns", "exec", namespace,
			"timeout", seconds, "bash", "-c",
			fmt.Sprintf("exec 3<>/dev/tcp/%s/%s", host, port)); err != nil {
			reasons = append(reasons, "tcp probe: "+checks.TCPAddress+" is unreachable through the tunnel")
		}
	}

	if checks.HTTPSURL != "" {
		ran++
		if _, err := url.Parse(checks.HTTPSURL); err != nil {
			reasons = append(reasons, "https probe: "+err.Error())
		} else if _, err := h.run(ctx, "ip", "netns", "exec", namespace,
			"curl", "-sS", "--max-time", seconds, "-o", "/dev/null", checks.HTTPSURL); err != nil {
			reasons = append(reasons, "https probe: "+checks.HTTPSURL+" failed through the tunnel")
		}
	}

	if checks.DNSName != "" {
		ran++
		if _, err := h.run(ctx, "ip", "netns", "exec", namespace,
			"timeout", seconds, "getent", "hosts", checks.DNSName); err != nil {
			reasons = append(reasons, "dns probe: "+checks.DNSName+" did not resolve through the tunnel")
		}
	}
	return reasons, ran
}
