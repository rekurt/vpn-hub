package health

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

// A tunnel with nothing configured used to come back healthy without a single packet
// being sent, which is the most dangerous answer this can give: the operator stops
// looking at a tunnel that may be dead.
func TestUnprobedTunnelIsUnknownNotHealthy(t *testing.T) {
	t.Parallel()
	health, err := ProbeChecker{}.Check(context.Background(), domain.Tunnel{ID: "corp"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthUnknown {
		t.Fatalf("Status = %q, want %q", health.Status, domain.HealthUnknown)
	}
	if health.Reason == "" {
		t.Error("an unknown result must explain why nothing was measured")
	}
}

func TestPassingProbeIsHealthy(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	health, err := ProbeChecker{Timeout: 2 * time.Second}.Check(context.Background(), domain.Tunnel{
		ID:     "corp",
		Health: domain.HealthCheck{TCPAddress: listener.Addr().String()},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthHealthy {
		t.Fatalf("Status = %q (%s), want healthy", health.Status, health.Reason)
	}
}

func TestFailingProbeIsUnhealthy(t *testing.T) {
	t.Parallel()
	health, err := ProbeChecker{Timeout: time.Second}.Check(context.Background(), domain.Tunnel{
		ID: "corp",
		// Port 1 on the loopback refuses connections immediately.
		Health: domain.HealthCheck{TCPAddress: "127.0.0.1:1"},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if health.Status != domain.HealthUnhealthy {
		t.Fatalf("Status = %q, want unhealthy", health.Status)
	}
	if !strings.Contains(health.Reason, "tcp probe") {
		t.Errorf("Reason = %q, want it to name the failing probe", health.Reason)
	}
}

// Knowing that two probes failed says something different from knowing only about
// whichever ran last; the reason used to be overwritten.
func TestReasonsFromSeveralProbesAccumulate(t *testing.T) {
	t.Parallel()
	health, err := ProbeChecker{Timeout: time.Second}.Check(context.Background(), domain.Tunnel{
		ID: "corp",
		Health: domain.HealthCheck{
			TCPAddress: "127.0.0.1:1",
			HTTPSURL:   "https://127.0.0.1:1/",
		},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(health.Reason, "tcp probe") || !strings.Contains(health.Reason, "https probe") {
		t.Fatalf("Reason = %q, want both failures reported", health.Reason)
	}
}
