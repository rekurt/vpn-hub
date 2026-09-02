package bot

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden pins a rendered screen, keyboard included: every user-visible string
// lives in render.go, so a wording change shows up as a reviewable diff.
func golden(t *testing.T, locale Locale, name, text string, markup *tg.InlineKeyboardMarkup) {
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

	path := filepath.Join("testdata", string(locale), name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
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

func renderLocales(t *testing.T, name string, render func(Localizer) (string, *tg.InlineKeyboardMarkup)) {
	t.Helper()
	var englishCallbacks [][]string
	for _, locale := range []Locale{LocaleEnglish, LocaleRussian} {
		locale := locale
		t.Run(string(locale), func(t *testing.T) {
			l, err := newStrictLocalizer(locale)
			if err != nil {
				t.Fatal(err)
			}
			text, markup := render(l)
			golden(t, locale, name, text, markup)
			callbacks := callbackData(markup)
			if locale == LocaleEnglish {
				englishCallbacks = callbacks
				return
			}
			if !reflect.DeepEqual(callbacks, englishCallbacks) {
				t.Fatalf("callback data differs by locale:\nEnglish: %#v\nRussian: %#v", englishCallbacks, callbacks)
			}
		})
	}
}

func callbackData(markup *tg.InlineKeyboardMarkup) [][]string {
	if markup == nil {
		return nil
	}
	rows := make([][]string, len(markup.InlineKeyboard))
	for rowIndex, row := range markup.InlineKeyboard {
		rows[rowIndex] = make([]string, len(row))
		for buttonIndex, button := range row {
			rows[rowIndex][buttonIndex] = button.CallbackData
		}
	}
	return rows
}

var renderNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

func TestRenderMain(t *testing.T) {
	t.Parallel()
	renderLocales(t, "main.golden", renderMain)
}

func TestRenderStatus(t *testing.T) {
	t.Parallel()
	view := statusView{
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
	}
	renderLocales(t, "status.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderStatus(l, view)
	})
}

func TestRenderDeployPreview(t *testing.T) {
	t.Parallel()
	current := domain.DesiredState{
		Revision: "6b419dc34476ad09",
		Tunnels:  []domain.Tunnel{{ID: "wg-nl"}},
		Devices:  []domain.DeployedDevice{{ID: "macbook", Egress: "direct"}},
	}
	view := deployView{
		Current: &current,
		Next: domain.DesiredState{
			Revision: "feedface00001111",
			Tunnels:  []domain.Tunnel{{ID: "wg-nl"}, {ID: "xray-de"}},
			Devices:  []domain.DeployedDevice{{ID: "macbook", Egress: "wg-nl"}, {ID: "phone", Egress: "direct"}},
		},
		Revoked: []string{"old-phone"},
	}
	renderLocales(t, "deploy_preview.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		localizedView := view
		localizedView.Changes = diffStates(l, view.Current, view.Next)
		return renderDeployPreview(l, localizedView)
	})
}

func TestRenderCountdown(t *testing.T) {
	t.Parallel()
	renderLocales(t, "countdown.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderCountdown(l, "feedface00001111", 3*time.Minute+20*time.Second)
	})
}

func TestRenderRefreshResult(t *testing.T) {
	t.Parallel()
	renderLocales(t, "refresh_result.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderRefreshResult(l, "xray-de",
			domain.ProxyTunnel{Server: "1.2.3.4", Port: 443},
			1,
			"agent is inactive")
	})
}

func TestRenderTunnelCard(t *testing.T) {
	t.Parallel()
	enabled := true
	entry := tunnelEntry{
		Tunnel: domain.Tunnel{
			ID: "corp-a", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork,
			Enabled:  &enabled,
			Source:   domain.TunnelSource{Kind: domain.SourceConfig, Value: "corp-a.conf"},
			Routes:   []string{"10.20.0.0/16"},
			DNSZones: []string{"corp.internal"},
		},
		Health: &healthEntry{ID: "corp-a", Status: domain.HealthHealthy, Reason: "handshake 10s ago", CheckedAt: renderNow.Add(-30 * time.Second)},
	}
	renderLocales(t, "tunnel_card.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderTunnelCard(l, entry, renderNow)
	})
}

func TestRenderTunnels(t *testing.T) {
	t.Parallel()
	enabled, disabled := true, false
	entries := []tunnelEntry{
		{Tunnel: domain.Tunnel{ID: "corp-a", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork, Enabled: &enabled}, Health: &healthEntry{Status: domain.HealthHealthy}},
		{Tunnel: domain.Tunnel{ID: "xray-de", Type: domain.TunnelXray, Role: domain.RoleEgress, Enabled: &disabled}},
	}
	renderLocales(t, "tunnels.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderTunnels(l, entries)
	})
}

func TestRenderDeviceList(t *testing.T) {
	t.Parallel()
	devices := []deviceEntry{
		{ID: "macbook", Address: "10.80.0.2/32", Egress: "wg-nl"},
		{ID: "old-phone", Address: "10.80.0.3/32", Egress: "direct", Revoked: true},
	}
	renderLocales(t, "devices.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderDevices(l, devices)
	})
}

func TestRenderSettings(t *testing.T) {
	t.Parallel()
	enabled := map[string]bool{}
	for _, category := range notificationCategories {
		enabled[category.Key] = true
	}
	enabled["converge"] = false
	notifications := Notifications{
		HealthInterval:      5 * time.Minute,
		DriftInterval:       30 * time.Minute,
		SubscriptionRefresh: 6 * time.Hour,
	}
	renderLocales(t, "settings.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderSettings(l, enabled, notifications)
	})
}

func TestRenderHub(t *testing.T) {
	t.Parallel()
	hub := domain.Hub{
		Endpoint:        "vpn.example.test:51820",
		ServerPublicKey: "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=",
		ClientCIDR:      "10.80.0.0/24",
		DNSAddress:      "10.80.0.1",
		AWGInterface:    map[string]string{"jc": "5", "jmin": "50"},
	}
	renderLocales(t, "hub.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderHub(l, hub)
	})
}

func TestRenderProbes(t *testing.T) {
	t.Parallel()
	health := domain.HealthCheck{
		HTTPSURL: "https://intranet.corp.internal/health",
	}
	renderLocales(t, "probes.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderProbes(l, "corp-a", health)
	})
}

func TestRenderSubCard(t *testing.T) {
	t.Parallel()
	entry := subEntry{
		ID: "xray-de", Enabled: true, Upstream: "1.2.3.4:443", LastGood: true,
		Health: &healthEntry{Status: domain.HealthHealthy, Reason: "2 probe(s) succeeded through the proxy"},
	}
	renderLocales(t, "sub_card.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderSubCard(l, entry)
	})
}

func TestRenderCandidates(t *testing.T) {
	t.Parallel()
	candidates := make([]domain.ProxyTunnel, 11)
	for index := range candidates {
		candidates[index] = domain.ProxyTunnel{Server: fmt.Sprintf("10.0.0.%d", index+1), Port: 443}
	}
	renderLocales(t, "candidates.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderCandidates(l, "xray-de", candidates, 1, "10.0.0.9:443")
	})
}

func TestRenderAccess(t *testing.T) {
	t.Parallel()
	renderLocales(t, "access.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderAccess(l, "wg-nl", []string{"laptop", "macbook", "phone"}, []string{"macbook"})
	})
}

func TestRenderConfirm(t *testing.T) {
	t.Parallel()
	renderLocales(t, "confirm.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderConfirm(l, "Continue with operation?", "op:yes", "op:no")
	})
}

func TestRenderConfirmWithinChoice(t *testing.T) {
	t.Parallel()
	renderLocales(t, "confirm_within.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderConfirmWithinChoice(l, "feedface00001111")
	})
}

func TestRenderCountdownOverdue(t *testing.T) {
	t.Parallel()
	renderLocales(t, "countdown_overdue.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderCountdownOverdue(l, "feedface00001111")
	})
}

func TestRenderRefreshFailure(t *testing.T) {
	t.Parallel()
	renderLocales(t, "refresh_failure.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderRefreshFailure(l, "xray-de", 1, subscriptionFailureProbe)
	})
}

func TestRenderEgressChoice(t *testing.T) {
	t.Parallel()
	renderLocales(t, "egress_choice.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderEgressChoice(l, "macbook", "wg-nl", []string{"wg-nl", "corp-a", "direct"})
	})
}

func TestRenderHost(t *testing.T) {
	t.Parallel()
	view := hostView{
		Snapshot: linux.HostSnapshot{
			Uptime: 26*time.Hour + 3*time.Minute, Load1: "0.15", Load5: "0.10", Load15: "0.05",
			DiskTotal: 25 << 30, DiskFree: 18 << 30,
		},
		Units: []linux.UnitStatus{
			{Unit: "vpn-hub-agent.service", Active: "active", Sub: "running"},
			{Unit: "vpn-hub-proxy-nl.service", Active: "active", Sub: "running", Restarts: 1},
		},
	}
	renderLocales(t, "host.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderHost(l, view)
	})
}

func TestRenderLogsMenu(t *testing.T) {
	t.Parallel()
	units := []linux.UnitStatus{
		{Unit: "vpn-hub-agent.service", Active: "active", Sub: "running"},
		{Unit: "vpn-hub-proxy-nl.service", Active: "active", Sub: "running"},
	}
	renderLocales(t, "logs_menu.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderLogsMenu(l, units)
	})
}

func TestRenderLogTail(t *testing.T) {
	t.Parallel()
	renderLocales(t, "log_tail.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderLogTail(l, "vpn-hub-agent.service", "ready\npeer <macbook> connected")
	})
}

func TestRenderSubs(t *testing.T) {
	t.Parallel()
	entries := []subEntry{
		{ID: "xray-de", Enabled: true, Upstream: "1.2.3.4:443", LastGood: true,
			Health: &healthEntry{Status: domain.HealthHealthy}},
		{ID: "xray-nl", Enabled: false},
	}
	renderLocales(t, "subs.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderSubs(l, entries, 6*time.Hour)
	})
}

func TestRenderDeviceCardOnline(t *testing.T) {
	t.Parallel()
	device := deviceEntry{
		ID: "macbook", Address: "10.80.0.2/32", PublicKey: "6OUoSDjcaLflZn3V7U3aO6eW1Mn5HE4xPJYmzoVvnhU=",
		Egress: "wg-nl", Now: renderNow,
		Peer: &domain.PeerObservation{
			LatestHandshake: renderNow.Add(-40 * time.Second),
			RxBytes:         3 << 30, TxBytes: 512 << 20,
		},
	}
	renderLocales(t, "device_card.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderDeviceCard(l, device)
	})
}

// A journal full of angle brackets must not push the escaped message past
// Telegram's 4096-char cap and lose the whole screen.
func TestRenderLogTailStaysUnderTheCap(t *testing.T) {
	t.Parallel()
	var lines []string
	for i := 0; i < 400; i++ {
		lines = append(lines, "line with <angle> & \"quote\" chars that esc() expands")
	}
	l, err := newStrictLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := renderLogTail(l, "vpn-hub-agent.service", strings.Join(lines, "\n"))
	if n := len([]rune(text)); n > 4096 {
		t.Fatalf("rendered log is %d runes, over the 4096 cap", n)
	}
	if strings.Contains(text, "<angle>") {
		t.Fatal("raw angle brackets leaked into the message")
	}
}

// shorten must cut on rune boundaries, never mid-rune, or Telegram rejects the
// invalid UTF-8 with a 400.
func TestShortenKeepsValidUTF8(t *testing.T) {
	t.Parallel()
	cut := shorten("привет-мир-сервер", 6)
	if !utf8.ValidString(cut) {
		t.Fatalf("shorten produced invalid UTF-8: %q", cut)
	}
	if []rune(cut)[0] != 'п' {
		t.Fatalf("unexpected prefix %q", cut)
	}
}

// The subscription URL carries a token; the tunnel card must never echo it.
func TestTunnelCardHidesSubscriptionURL(t *testing.T) {
	t.Parallel()
	l, err := newStrictLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := renderTunnelCard(l, tunnelEntry{Tunnel: domain.Tunnel{
		ID: "xray-de", Type: domain.TunnelXray, Role: domain.RoleEgress,
		Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/secret-token"},
	}}, renderNow)
	if strings.Contains(text, "secret-token") {
		t.Fatalf("the subscription URL leaked:\n%s", text)
	}
}

func TestRenderClientACLs(t *testing.T) {
	t.Parallel()
	entries := []clientACLEntry{{Rule: domain.ClientACL{Source: "phone", Target: "macbook", Protocol: domain.ClientACLTCP, Port: 22}, Ordinal: 0}}
	renderLocales(t, "client_acls.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderClientACLs(l, entries)
	})
}

func TestRenderClientACLSource(t *testing.T) {
	t.Parallel()
	renderLocales(t, "client_acl_source.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderClientACLSource(l, []string{"macbook", "phone"})
	})
}

func TestRenderClientACLTarget(t *testing.T) {
	t.Parallel()
	renderLocales(t, "client_acl_target.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderClientACLTarget(l, "phone", []string{"macbook", "phone"})
	})
}

func TestRenderRoutes(t *testing.T) {
	t.Parallel()
	lines := []routeLine{
		{Destination: "0.0.0.0/0", Via: "wg-nl", Why: "device macbook egress"},
		{Destination: "10.20.0.0/16", Via: "corp-a", Why: "private network"},
	}
	renderLocales(t, "routes.golden", func(l Localizer) (string, *tg.InlineKeyboardMarkup) {
		return renderRoutes(l, lines)
	})
}

func TestRenderLocalizedFormatting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		locale       Locale
		durationDays string
		duration     string
		never        string
		justNow      string
		ago          string
		bytes        string
		on           string
		off          string
	}{
		{LocaleEnglish, "2d 5h", "3m 20s", "never", "just now", "5m ago", "1.0 GiB", "on", "off"},
		{LocaleRussian, "2д 5ч", "3м 20с", "никогда", "только что", "5м назад", "1.0 ГиБ", "вкл", "выкл"},
	}
	for _, tt := range tests {
		t.Run(string(tt.locale), func(t *testing.T) {
			l, err := newStrictLocalizer(tt.locale)
			if err != nil {
				t.Fatal(err)
			}
			if got := formatDuration(l, 53*time.Hour); got != tt.durationDays {
				t.Errorf("formatDuration(days) = %q, want %q", got, tt.durationDays)
			}
			if got := formatDuration(l, 3*time.Minute+20*time.Second); got != tt.duration {
				t.Errorf("formatDuration = %q, want %q", got, tt.duration)
			}
			if got := formatAge(l, renderNow, time.Time{}); got != tt.never {
				t.Errorf("formatAge(zero) = %q, want %q", got, tt.never)
			}
			if got := formatAge(l, renderNow, renderNow.Add(-20*time.Second)); got != tt.justNow {
				t.Errorf("formatAge(now) = %q, want %q", got, tt.justNow)
			}
			if got := formatAge(l, renderNow, renderNow.Add(-5*time.Minute)); got != tt.ago {
				t.Errorf("formatAge(ago) = %q, want %q", got, tt.ago)
			}
			if got := formatBytes(l, 1<<30); got != tt.bytes {
				t.Errorf("formatBytes = %q, want %q", got, tt.bytes)
			}
			if got := onOff(l, true); got != tt.on {
				t.Errorf("onOff(true) = %q, want %q", got, tt.on)
			}
			if got := onOff(l, false); got != tt.off {
				t.Errorf("onOff(false) = %q, want %q", got, tt.off)
			}
		})
	}
}
