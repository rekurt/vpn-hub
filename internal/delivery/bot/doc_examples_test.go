package bot

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

var updateDocs = flag.Bool("update-docs", false, "rewrite bot documentation examples")

var documentationScreenIDs = []string{
	"candidates",
	"client-acls",
	"deploy-countdown",
	"deploy-preview",
	"device-card",
	"devices",
	"host",
	"hub",
	"logs",
	"main",
	"settings",
	"status",
	"subscription-card",
	"subscriptions",
	"tunnel-card",
	"tunnels",
}

type documentationScreen struct {
	ID     string                  `json:"id"`
	Locale Locale                  `json:"locale"`
	Title  string                  `json:"title"`
	Text   string                  `json:"text"`
	Rows   [][]documentationButton `json:"rows"`
}

type documentationButton struct {
	Label    string `json:"label"`
	Callback string `json:"callback"`
}

func TestDocumentationExamples(t *testing.T) {
	for _, locale := range []Locale{LocaleEnglish, LocaleRussian} {
		locale := locale
		t.Run(string(locale), func(t *testing.T) {
			l, err := newStrictLocalizer(locale)
			if err != nil {
				t.Fatal(err)
			}

			generated, err := documentationExamples(l)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "..", "..", "site", "src", "data", "bot-screens."+string(locale)+".json")
			if *updateDocs {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, generated, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			committed, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing documentation examples (run `go test ./internal/delivery/bot -run TestDocumentationExamples -update-docs`): %v", err)
			}
			if !bytes.Equal(committed, generated) {
				t.Fatalf("documentation examples differ from %s (run `go test ./internal/delivery/bot -run TestDocumentationExamples -update-docs`)", path)
			}
		})
	}
}

func documentationExamples(l Localizer) ([]byte, error) {
	type renderedScreen struct {
		id      string
		titleID MessageID
		render  func() (string, *tg.InlineKeyboardMarkup)
	}

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	enabled := true
	disabled := false
	current := domain.DesiredState{
		Revision: "docs-current-0001",
		Tunnels:  []domain.Tunnel{{ID: "docs-egress"}},
		Devices:  []domain.DeployedDevice{{ID: "docs-laptop", Egress: "direct"}},
	}
	next := domain.DesiredState{
		Revision: "docs-next-0002",
		Tunnels: []domain.Tunnel{
			{ID: "docs-egress"},
			{ID: "docs-private"},
		},
		Devices: []domain.DeployedDevice{
			{ID: "docs-laptop", Egress: "docs-egress"},
			{ID: "docs-phone", Egress: "direct"},
		},
	}
	device := deviceEntry{
		ID: "docs-laptop", Address: "192.0.2.10/32", PublicKey: "PUBLIC-KEY-EXAMPLE",
		Egress: "docs-egress", Now: now,
		Peer: &domain.PeerObservation{LatestHandshake: now.Add(-40 * time.Second), RxBytes: 3 << 30, TxBytes: 512 << 20},
	}
	tunnel := tunnelEntry{Tunnel: domain.Tunnel{
		ID: "docs-private", Type: domain.TunnelWireGuard, Role: domain.RolePrivateNetwork,
		Enabled: &enabled, Source: domain.TunnelSource{Kind: domain.SourceConfig, Value: "docs-private.conf"},
		Routes: []string{"198.51.100.0/24"}, DNSZones: []string{"docs.example.test"},
	}, Health: &healthEntry{ID: "docs-private", Status: domain.HealthHealthy, Reason: "handshake 10s ago", CheckedAt: now.Add(-30 * time.Second)}}

	screens := []renderedScreen{
		{"main", MsgMainTitle, func() (string, *tg.InlineKeyboardMarkup) { return renderMain(l) }},
		{"status", msgStatusTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderStatus(l, statusView{Now: now, State: &domain.DesiredState{Revision: "docs-current-0001", GeneratedAt: now.Add(-2 * time.Hour), Tunnels: make([]domain.Tunnel, 2), Devices: make([]domain.DeployedDevice, 2)}, Pending: &runtimeadapter.Pending{Revision: "docs-next-0002", Deadline: now.Add(3*time.Minute + 20*time.Second)}, Agent: &linux.UnitStatus{Unit: agentUnit, Active: "active", Sub: "running"}, HealthEvery: 5 * time.Minute})
		}},
		{"devices", msgDevicesTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderDevices(l, []deviceEntry{device, {ID: "docs-phone", Address: "192.0.2.11/32", Egress: "direct", Revoked: true}})
		}},
		{"device-card", MsgButtonDevices, func() (string, *tg.InlineKeyboardMarkup) { return renderDeviceCard(l, device) }},
		{"tunnels", msgTunnelsTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderTunnels(l, []tunnelEntry{tunnel, {Tunnel: domain.Tunnel{ID: "docs-egress", Type: domain.TunnelXray, Role: domain.RoleEgress, Enabled: &disabled}}})
		}},
		{"tunnel-card", msgButtonTunnels, func() (string, *tg.InlineKeyboardMarkup) { return renderTunnelCard(l, tunnel, now) }},
		{"deploy-preview", msgDeployTitle, func() (string, *tg.InlineKeyboardMarkup) {
			view := deployView{Current: &current, Next: next, Revoked: []string{"docs-retired"}}
			view.Changes = diffStates(l, view.Current, view.Next)
			return renderDeployPreview(l, view)
		}},
		{"deploy-countdown", msgDeployTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderCountdown(l, "docs-next-0002", 3*time.Minute+20*time.Second)
		}},
		{"subscriptions", msgSubsTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderSubs(l, []subEntry{{ID: "docs-egress", Enabled: true, Upstream: "203.0.113.44:443", LastGood: true, Health: &healthEntry{Status: domain.HealthHealthy}}}, 6*time.Hour)
		}},
		{"subscription-card", msgButtonSubscriptions, func() (string, *tg.InlineKeyboardMarkup) {
			return renderSubCard(l, subEntry{ID: "docs-egress", Enabled: true, Upstream: "203.0.113.44:443", LastGood: true, Health: &healthEntry{Status: domain.HealthHealthy, Reason: "probe passed"}})
		}},
		{"candidates", msgButtonCandidates, func() (string, *tg.InlineKeyboardMarkup) {
			return renderCandidates(l, "docs-egress", []domain.ProxyTunnel{{Server: "203.0.113.44", Port: 443}, {Server: "198.51.100.44", Port: 8443}}, 0, "203.0.113.44:443")
		}},
		{"client-acls", msgACLTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderClientACLs(l, []clientACLEntry{{Rule: domain.ClientACL{Source: "docs-phone", Target: "docs-laptop", Protocol: domain.ClientACLTCP, Port: 22}, Ordinal: 0}})
		}},
		{"logs", msgLogsTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderLogsMenu(l, []linux.UnitStatus{{Unit: "vpn-hub-agent.service", Active: "active", Sub: "running"}, {Unit: "vpn-hub-docs.service", Active: "active", Sub: "running"}})
		}},
		{"host", msgHostTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderHost(l, hostView{Snapshot: linux.HostSnapshot{Uptime: 26*time.Hour + 3*time.Minute, Load1: "0.15", Load5: "0.10", Load15: "0.05", DiskTotal: 25 << 30, DiskFree: 18 << 30}, Units: []linux.UnitStatus{{Unit: "vpn-hub-agent.service", Active: "active", Sub: "running"}}})
		}},
		{"hub", msgHubTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderHub(l, domain.Hub{Endpoint: "hub.example.test:51820", ServerPublicKey: "PUBLIC-KEY-EXAMPLE", ClientCIDR: "192.0.2.0/24", DNSAddress: "192.0.2.1", AWGInterface: map[string]string{"jc": "5", "jmin": "50"}})
		}},
		{"settings", msgSettingsTitle, func() (string, *tg.InlineKeyboardMarkup) {
			return renderSettings(l, map[string]bool{"rollback": true, "agent-error": true, "converge": false, "health": true, "drift": true, "subscription": true, "oob": true}, Notifications{HealthInterval: 5 * time.Minute, DriftInterval: 30 * time.Minute, SubscriptionRefresh: 6 * time.Hour})
		}},
	}

	examples := make([]documentationScreen, 0, len(screens))
	for _, screen := range screens {
		text, markup := screen.render()
		examples = append(examples, documentationScreen{ID: screen.id, Locale: l.Locale(), Title: documentationTitle(l, screen.titleID), Text: text, Rows: documentationRows(markup)})
	}
	sort.Slice(examples, func(i, j int) bool { return examples[i].ID < examples[j].ID })
	if len(examples) != len(documentationScreenIDs) {
		return nil, fmt.Errorf("documentation screens = %d, want %d", len(examples), len(documentationScreenIDs))
	}
	for i, id := range documentationScreenIDs {
		if examples[i].ID != id {
			return nil, fmt.Errorf("documentation screen %d = %q, want %q", i, examples[i].ID, id)
		}
	}

	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(examples); err != nil {
		return nil, fmt.Errorf("encode documentation examples: %w", err)
	}
	return output.Bytes(), nil
}

func documentationTitle(l Localizer, id MessageID) string {
	title := l.Text(id)
	title = strings.NewReplacer("<b>", "", "</b>", "", "<code>", "", "</code>", "").Replace(title)
	return strings.TrimSpace(strings.SplitN(title, "\n", 2)[0])
}

func documentationRows(markup *tg.InlineKeyboardMarkup) [][]documentationButton {
	if markup == nil {
		return nil
	}
	rows := make([][]documentationButton, len(markup.InlineKeyboard))
	for i, row := range markup.InlineKeyboard {
		rows[i] = make([]documentationButton, len(row))
		for j, button := range row {
			rows[i][j] = documentationButton{Label: button.Text, Callback: button.CallbackData}
		}
	}
	return rows
}
