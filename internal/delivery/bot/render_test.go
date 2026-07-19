package bot

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden pins a rendered screen, keyboard included: every user-visible string
// lives in render.go, so a wording change shows up as a reviewable diff.
func golden(t *testing.T, name, text string, markup *tg.InlineKeyboardMarkup) {
	t.Helper()
	var b strings.Builder
	b.WriteString(text)
	b.WriteString("\n--- keyboard ---\n")
	if markup != nil {
		for _, row := range markup.InlineKeyboard {
			for index, button := range row {
				if index > 0 {
					b.WriteString(" | ")
				}
				fmt.Fprintf(&b, "[%s](%s)", button.Text, button.CallbackData)
			}
			b.WriteString("\n")
		}
	}
	rendered := b.String()

	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden (run `go test ./internal/delivery/bot -update`): %v", err)
	}
	if string(expected) != rendered {
		t.Errorf("screen differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, rendered, string(expected))
	}
}

var renderNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

func TestRenderMain(t *testing.T) {
	t.Parallel()
	text, markup := renderMain()
	golden(t, "main.golden", text, markup)
}

func TestRenderStatus(t *testing.T) {
	t.Parallel()
	text, markup := renderStatus(statusView{
		Now: renderNow,
		State: &domain.DesiredState{
			Revision:    "6b419dc34476ad09",
			GeneratedAt: renderNow.Add(-2 * time.Hour),
			Tunnels:     make([]domain.Tunnel, 3),
			Devices:     make([]domain.DeployedDevice, 2),
		},
		Pending: &runtimeadapter.Pending{Revision: "aaaa000011112222", Deadline: renderNow.Add(3*time.Minute + 20*time.Second)},
		Agent:   &linux.UnitStatus{Unit: agentUnit, Active: "active", Sub: "running", Restarts: 1},
		Drift: []domain.Operation{
			{Kind: domain.OpUpdate, Resource: domain.ResourceRef{Type: "ingress", ID: "awg0"}, Reason: "peer set differs"},
		},
		Health: []healthEntry{
			{ID: "corp-a", Status: domain.HealthHealthy, Reason: "handshake 10s ago", CheckedAt: renderNow.Add(-4 * time.Minute)},
			{ID: "wg-nl", Status: domain.HealthUnhealthy, Reason: "the tunnel has never completed a handshake", CheckedAt: renderNow.Add(-4 * time.Minute)},
			{ID: "xray-de", Status: domain.HealthUnknown, Reason: "nothing was measured", CheckedAt: renderNow.Add(-4 * time.Minute)},
		},
		HealthEvery: 5 * time.Minute,
	})
	golden(t, "status.golden", text, markup)
}

func TestRenderDeployPreview(t *testing.T) {
	t.Parallel()
	current := domain.DesiredState{Revision: "6b419dc34476ad09"}
	text, markup := renderDeployPreview(deployView{
		Current: &current,
		Next:    domain.DesiredState{Revision: "feedface00001111", Tunnels: make([]domain.Tunnel, 2), Devices: make([]domain.DeployedDevice, 2)},
		Revoked: []string{"old-phone"},
		Changes: []string{"➕ туннель xray-de", "🔀 macbook: direct → wg-nl"},
	})
	golden(t, "deploy_preview.golden", text, markup)
}

func TestRenderCountdown(t *testing.T) {
	t.Parallel()
	text, markup := renderCountdown("feedface00001111", 3*time.Minute+20*time.Second)
	golden(t, "countdown.golden", text, markup)
}

func TestRenderRefreshResult(t *testing.T) {
	t.Parallel()
	text, markup := renderRefreshResult("xray-de",
		domain.ProxyTunnel{Server: "1.2.3.4", Port: 443},
		[]string{"5.6.7.8:443: the candidate did not carry traffic: timeout"},
		"⚠️ Агент сейчас не работает (inactive) — изменение не применится, пока он не запустится.")
	golden(t, "refresh_result.golden", text, markup)
}

func TestRenderTunnelCard(t *testing.T) {
	t.Parallel()
	enabled := true
	text, markup := renderTunnelCard(tunnelEntry{
		Tunnel: domain.Tunnel{
			ID: "corp-a", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork,
			Enabled:  &enabled,
			Source:   domain.TunnelSource{Kind: domain.SourceConfig, Value: "corp-a.conf"},
			Routes:   []string{"10.20.0.0/16"},
			DNSZones: []string{"corp.internal"},
		},
		Health: &healthEntry{ID: "corp-a", Status: domain.HealthHealthy, Reason: "handshake 10s ago", CheckedAt: renderNow.Add(-30 * time.Second)},
	}, renderNow)
	golden(t, "tunnel_card.golden", text, markup)
}

func TestRenderDeviceList(t *testing.T) {
	t.Parallel()
	text, markup := renderDevices([]deviceEntry{
		{ID: "macbook", Address: "10.80.0.2/32", Egress: "wg-nl"},
		{ID: "old-phone", Address: "10.80.0.3/32", Egress: "direct", Revoked: true},
	})
	golden(t, "devices.golden", text, markup)
}

func TestRenderSettings(t *testing.T) {
	t.Parallel()
	enabled := map[string]bool{}
	for _, category := range notificationCategories {
		enabled[category.Key] = true
	}
	enabled["converge"] = false
	text, markup := renderSettings(enabled, Notifications{
		HealthInterval:      5 * time.Minute,
		DriftInterval:       30 * time.Minute,
		SubscriptionRefresh: 6 * time.Hour,
	})
	golden(t, "settings.golden", text, markup)
}

// The subscription URL carries a token; the tunnel card must never echo it.
func TestTunnelCardHidesSubscriptionURL(t *testing.T) {
	t.Parallel()
	text, _ := renderTunnelCard(tunnelEntry{Tunnel: domain.Tunnel{
		ID: "xray-de", Type: domain.TunnelXray, Role: domain.RoleEgress,
		Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/secret-token"},
	}}, renderNow)
	if strings.Contains(text, "secret-token") {
		t.Fatalf("the subscription URL leaked:\n%s", text)
	}
}
