package bot

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

// Renderers are pure: localized data in, Telegram HTML and keyboard out.

const (
	msgButtonTunnels            MessageID = "button/tunnels"
	msgButtonSubscriptions      MessageID = "button/subscriptions"
	msgButtonDeploy             MessageID = "button/deploy"
	msgButtonRoutes             MessageID = "button/routes"
	msgButtonClientACLs         MessageID = "button/client_acls"
	msgButtonLogs               MessageID = "button/logs"
	msgButtonHost               MessageID = "button/host"
	msgButtonHub                MessageID = "button/hub"
	msgButtonSettings           MessageID = "button/settings"
	msgButtonMenu               MessageID = "button/menu"
	msgButtonRefresh            MessageID = "button/refresh"
	msgButtonConfirm            MessageID = "button/confirm"
	msgButtonRollback           MessageID = "button/rollback"
	msgButtonBack               MessageID = "button/back"
	msgButtonCancel             MessageID = "button/cancel"
	msgFormatDurationDay        MessageID = "format/duration/day"
	msgFormatDurationDayHour    MessageID = "format/duration/day_hour"
	msgFormatDurationHour       MessageID = "format/duration/hour"
	msgFormatDurationHourMinute MessageID = "format/duration/hour_minute"
	msgFormatDurationMinute     MessageID = "format/duration/minute"
	msgFormatDurationMinuteSec  MessageID = "format/duration/minute_second"
	msgFormatDurationSecond     MessageID = "format/duration/second"
	msgFormatAgeNever           MessageID = "format/age/never"
	msgFormatAgeJustNow         MessageID = "format/age/just_now"
	msgFormatAgeAgo             MessageID = "format/age/ago"
	msgFormatBytesGiB           MessageID = "format/bytes/gib"
	msgFormatBytesMiB           MessageID = "format/bytes/mib"
	msgFormatBytesKiB           MessageID = "format/bytes/kib"
	msgFormatBytesB             MessageID = "format/bytes/b"
	msgFormatOn                 MessageID = "format/on"
	msgFormatOff                MessageID = "format/off"
	msgPluralDiscrepancyOne     MessageID = "plural/discrepancy/one"
	msgPluralDiscrepancyFew     MessageID = "plural/discrepancy/few"
	msgPluralDiscrepancyMany    MessageID = "plural/discrepancy/many"
	msgPluralCandidateOne       MessageID = "plural/candidate/one"
	msgPluralCandidateFew       MessageID = "plural/candidate/few"
	msgPluralCandidateMany      MessageID = "plural/candidate/many"
	msgPluralTunnelOne          MessageID = "plural/tunnel/one"
	msgPluralTunnelFew          MessageID = "plural/tunnel/few"
	msgPluralTunnelMany         MessageID = "plural/tunnel/many"
	msgPluralDeviceOne          MessageID = "plural/device/one"
	msgPluralDeviceFew          MessageID = "plural/device/few"
	msgPluralDeviceMany         MessageID = "plural/device/many"
)

func esc(value string) string { return html.EscapeString(value) }

func btn(text, data string) tg.InlineKeyboardButton {
	return tg.InlineKeyboardButton{Text: text, CallbackData: data}
}

func keyboard(rows ...[]tg.InlineKeyboardButton) *tg.InlineKeyboardMarkup {
	return &tg.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func formatDuration(l Localizer, d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	switch {
	case hours >= 48 && hours%24 == 0:
		return l.Text(msgFormatDurationDay, hours/24)
	case hours >= 48:
		return l.Text(msgFormatDurationDayHour, hours/24, hours%24)
	case hours > 0 && minutes == 0:
		return l.Text(msgFormatDurationHour, hours)
	case hours > 0:
		return l.Text(msgFormatDurationHourMinute, hours, minutes)
	case minutes > 0 && seconds == 0:
		return l.Text(msgFormatDurationMinute, minutes)
	case minutes > 0:
		return l.Text(msgFormatDurationMinuteSec, minutes, seconds)
	default:
		return l.Text(msgFormatDurationSecond, seconds)
	}
}

func plural(l Localizer, count int, one, few, many MessageID) string {
	if l.Locale() == LocaleEnglish {
		if count == 1 {
			return l.Text(one)
		}
		return l.Text(many)
	}
	tail, hundred := count%10, count%100
	switch {
	case hundred >= 11 && hundred <= 14:
		return l.Text(many)
	case tail == 1:
		return l.Text(one)
	case tail >= 2 && tail <= 4:
		return l.Text(few)
	default:
		return l.Text(many)
	}
}

func formatAge(l Localizer, now, then time.Time) string {
	if then.IsZero() {
		return l.Text(msgFormatAgeNever)
	}
	age := now.Sub(then)
	if age < time.Minute {
		return l.Text(msgFormatAgeJustNow)
	}
	return l.Text(msgFormatAgeAgo, formatDuration(l, age))
}

func formatGiB(l Localizer, bytes uint64) string {
	return l.Text(msgFormatBytesGiB, float64(bytes)/(1<<30))
}

// formatBytes picks a readable unit: traffic counters range from kilobytes on a
// fresh peer to hundreds of gigabytes, and one fixed unit misreads both ends.
func formatBytes(l Localizer, bytes uint64) string {
	switch {
	case bytes >= 1<<30:
		return formatGiB(l, bytes)
	case bytes >= 1<<20:
		return l.Text(msgFormatBytesMiB, float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return l.Text(msgFormatBytesKiB, float64(bytes)/(1<<10))
	default:
		return l.Text(msgFormatBytesB, bytes)
	}
}

func healthIcon(status domain.HealthStatus) string {
	switch status {
	case domain.HealthHealthy:
		return "🟢"
	case domain.HealthUnhealthy:
		return "🔴"
	default:
		return "⚪️"
	}
}

func onOff(l Localizer, enabled bool) string {
	if enabled {
		return l.Text(msgFormatOn)
	}
	return l.Text(msgFormatOff)
}

// --- Main menu -------------------------------------------------------------

func renderMain(l Localizer) (string, *tg.InlineKeyboardMarkup) {
	text := l.Text(MsgMainTitle) + "\n" + l.Text(MsgMainIntro)
	return text, keyboard(
		[]tg.InlineKeyboardButton{btn("📊 "+l.Text(MsgButtonStatus), "st"), btn("📱 "+l.Text(MsgButtonDevices), "dev")},
		[]tg.InlineKeyboardButton{btn("🚇 "+l.Text(msgButtonTunnels), "tun"), btn("📡 "+l.Text(msgButtonSubscriptions), "sub")},
		[]tg.InlineKeyboardButton{btn("🚀 "+l.Text(msgButtonDeploy), "dep"), btn("🗺 "+l.Text(msgButtonRoutes), "rt")},
		[]tg.InlineKeyboardButton{btn("🔐 "+l.Text(msgButtonClientACLs), "acl")},
		[]tg.InlineKeyboardButton{btn("📜 "+l.Text(msgButtonLogs), "log"), btn("🖥 "+l.Text(msgButtonHost), "host")},
		[]tg.InlineKeyboardButton{btn("⚙️ "+l.Text(msgButtonHub), "hub"), btn("🔔 "+l.Text(msgButtonSettings), "set")},
	)
}

func backRow(l Localizer) []tg.InlineKeyboardButton {
	return []tg.InlineKeyboardButton{btn("🏠 "+l.Text(msgButtonMenu), "m")}
}

// --- Status ----------------------------------------------------------------

type healthEntry struct {
	ID        string
	Status    domain.HealthStatus
	Reason    string
	CheckedAt time.Time
}

type statusView struct {
	Now         time.Time
	State       *domain.DesiredState
	StateErr    string
	Pending     *runtimeadapter.Pending
	Agent       *linux.UnitStatus
	AgentErr    string
	Drift       []domain.Operation
	DriftErr    string
	Health      []healthEntry
	HealthEvery time.Duration
	// DevicesOnline counts fresh handshakes; -1 means the interface could not be
	// observed and nothing should be claimed.
	DevicesOnline int
	DevicesTotal  int
}

const (
	msgStatusTitle          MessageID = "status/title"
	msgStatusRevisionError  MessageID = "status/revision_error"
	msgStatusRevisionNone   MessageID = "status/revision_none"
	msgStatusRevision       MessageID = "status/revision"
	msgStatusResourceCounts MessageID = "status/resource_counts"
	msgStatusOnline         MessageID = "status/online"
	msgStatusPending        MessageID = "status/pending"
	msgStatusExpired        MessageID = "status/expired"
	msgStatusAgentError     MessageID = "status/agent_error"
	msgStatusAgent          MessageID = "status/agent"
	msgStatusDriftError     MessageID = "status/drift_error"
	msgStatusDriftConverged MessageID = "status/drift_converged"
	msgStatusDriftCount     MessageID = "status/drift_count"
	msgStatusMore           MessageID = "status/more"
	msgStatusOperation      MessageID = "status/operation"
	msgStatusHealthTitle    MessageID = "status/health_title"
	msgStatusHealthEntry    MessageID = "status/health_entry"
)

func renderStatus(l Localizer, view statusView) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgStatusTitle))

	switch {
	case view.StateErr != "":
		b.WriteString(l.Text(msgStatusRevisionError, esc(view.StateErr)))
	case view.State == nil:
		b.WriteString(l.Text(msgStatusRevisionNone))
	default:
		b.WriteString(l.Text(msgStatusRevision, esc(view.State.Revision), formatAge(l, view.Now, view.State.GeneratedAt)))
		tunnels := len(view.State.Tunnels)
		devices := len(view.State.Devices)
		b.WriteString(l.Text(msgStatusResourceCounts,
			tunnels, plural(l, tunnels, msgPluralTunnelOne, msgPluralTunnelFew, msgPluralTunnelMany),
			devices, plural(l, devices, msgPluralDeviceOne, msgPluralDeviceFew, msgPluralDeviceMany)))
	}
	if view.DevicesOnline >= 0 && view.DevicesTotal > 0 {
		b.WriteString(l.Text(msgStatusOnline, view.DevicesOnline, view.DevicesTotal))
	}

	if view.Pending != nil {
		left := view.Pending.Deadline.Sub(view.Now)
		if left > 0 {
			b.WriteString(l.Text(msgStatusPending, esc(view.Pending.Revision), formatDuration(l, left)))
		} else {
			b.WriteString(l.Text(msgStatusExpired, esc(view.Pending.Revision)))
		}
	}

	b.WriteString("\n")
	switch {
	case view.AgentErr != "":
		b.WriteString(l.Text(msgStatusAgentError, esc(view.AgentErr)))
	case view.Agent != nil:
		icon := "🔴"
		if view.Agent.Active == "active" {
			icon = "🟢"
		}
		b.WriteString(l.Text(msgStatusAgent, icon, esc(view.Agent.Active), esc(view.Agent.Sub), view.Agent.Restarts))
	}

	switch {
	case view.DriftErr != "":
		b.WriteString(l.Text(msgStatusDriftError, esc(view.DriftErr)))
	case len(view.Drift) == 0:
		b.WriteString(l.Text(msgStatusDriftConverged))
	default:
		b.WriteString(l.Text(msgStatusDriftCount, len(view.Drift), plural(l, len(view.Drift), msgPluralDiscrepancyOne, msgPluralDiscrepancyFew, msgPluralDiscrepancyMany)))
		for index, operation := range view.Drift {
			if index == 8 {
				b.WriteString(l.Text(msgStatusMore, len(view.Drift)-index))
				break
			}
			b.WriteString(l.Text(msgStatusOperation, esc(operation.String())))
		}
	}

	if len(view.Health) > 0 {
		b.WriteString(l.Text(msgStatusHealthTitle, formatDuration(l, view.HealthEvery)))
		for _, entry := range view.Health {
			b.WriteString(l.Text(msgStatusHealthEntry, healthIcon(entry.Status), esc(entry.ID), esc(entry.Reason), formatAge(l, view.Now, entry.CheckedAt)))
		}
	}

	rows := [][]tg.InlineKeyboardButton{{btn("🔄 "+l.Text(msgButtonRefresh), "st"), btn("🏠 "+l.Text(msgButtonMenu), "m")}}
	if view.Pending != nil {
		rows = append([][]tg.InlineKeyboardButton{{btn("✅ "+l.Text(msgButtonConfirm), "dep:ok"), btn("↩️ "+l.Text(msgButtonRollback), "dep:rb!")}}, rows...)
	}
	return b.String(), keyboard(rows...)
}

// --- Devices ---------------------------------------------------------------

type deviceEntry struct {
	ID        string
	Address   string
	PublicKey string
	Egress    string
	Revoked   bool
	// Peer is the live kernel state for this device's key; nil when the ingress
	// interface has no such peer (not yet deployed, or observation unavailable).
	Peer *domain.PeerObservation
	Now  time.Time
}

// online means the handshake is fresh enough that traffic flowed moments ago.
func (d deviceEntry) online() bool {
	return d.Peer != nil && !d.Peer.LatestHandshake.IsZero() &&
		d.Now.Sub(d.Peer.LatestHandshake) <= linux.HandshakeGrace
}

const (
	msgDevicePresenceNever  MessageID = "device/presence/never"
	msgDevicePresenceOnline MessageID = "device/presence/online"
	msgDevicePresenceAgo    MessageID = "device/presence/ago"
	msgDevicesTitle         MessageID = "devices/title"
	msgDevicesEmpty         MessageID = "devices/empty"
	msgDevicesRevokedMark   MessageID = "devices/revoked_mark"
	msgButtonAddDevice      MessageID = "button/add_device"
	msgDeviceAddress        MessageID = "device/address"
	msgDeviceEgress         MessageID = "device/egress"
	msgDeviceKey            MessageID = "device/key"
	msgDeviceTraffic        MessageID = "device/traffic"
	msgDeviceRevoked        MessageID = "device/revoked"
	msgButtonChangeEgress   MessageID = "button/change_egress"
	msgButtonSendProfile    MessageID = "button/send_profile"
	msgButtonReissueProfile MessageID = "button/reissue_profile"
	msgButtonRevoke         MessageID = "button/revoke"
	msgEgressChoice         MessageID = "egress/choice"
)

func (d deviceEntry) presence(l Localizer) string {
	switch {
	case d.Peer == nil || d.Peer.LatestHandshake.IsZero():
		return l.Text(msgDevicePresenceNever)
	case d.online():
		return l.Text(msgDevicePresenceOnline)
	default:
		return l.Text(msgDevicePresenceAgo, formatAge(l, d.Now, d.Peer.LatestHandshake))
	}
}

func (d deviceEntry) presenceIcon() string {
	switch {
	case d.Revoked:
		return "🚫"
	case d.online():
		return "🟢"
	default:
		return "⚪️"
	}
}

func renderDevices(l Localizer, devices []deviceEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgDevicesTitle))
	if len(devices) == 0 {
		b.WriteString(l.Text(msgDevicesEmpty))
	}
	for _, device := range devices {
		mark := ""
		if device.Revoked {
			mark = l.Text(msgDevicesRevokedMark)
		}
		fmt.Fprintf(&b, "%s <code>%s</code> → %s — %s%s\n",
			device.presenceIcon(), esc(device.ID), esc(device.Egress), device.presence(l), mark)
	}

	var rows [][]tg.InlineKeyboardButton
	for i := 0; i < len(devices); i += 2 {
		row := []tg.InlineKeyboardButton{btn(devices[i].ID, "dev:c:"+devices[i].ID)}
		if i+1 < len(devices) {
			row = append(row, btn(devices[i+1].ID, "dev:c:"+devices[i+1].ID))
		}
		rows = append(rows, row)
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("➕ "+l.Text(msgButtonAddDevice), "dev:add")}, backRow(l))
	return b.String(), keyboard(rows...)
}

func renderDeviceCard(l Localizer, device deviceEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	fmt.Fprintf(&b, "📱 <b>%s</b>\n\n", esc(device.ID))
	b.WriteString(l.Text(msgDeviceAddress, esc(device.Address)))
	b.WriteString(l.Text(msgDeviceEgress, esc(device.Egress)))
	b.WriteString(l.Text(msgDeviceKey, esc(shorten(device.PublicKey, 12))))
	fmt.Fprintf(&b, "\n%s %s\n", device.presenceIcon(), device.presence(l))
	if device.Peer != nil && (device.Peer.RxBytes > 0 || device.Peer.TxBytes > 0) {
		b.WriteString(l.Text(msgDeviceTraffic, formatBytes(l, device.Peer.RxBytes), formatBytes(l, device.Peer.TxBytes)))
	}
	if device.Revoked {
		b.WriteString(l.Text(msgDeviceRevoked))
	}
	rows := [][]tg.InlineKeyboardButton{
		{btn("🔀 "+l.Text(msgButtonChangeEgress), "dev:eg:"+device.ID)},
	}
	if !device.Revoked {
		rows = append(rows, []tg.InlineKeyboardButton{btn("📄 "+l.Text(msgButtonSendProfile), "dev:pr:"+device.ID)})
		rows = append(rows, []tg.InlineKeyboardButton{btn("📤 "+l.Text(msgButtonReissueProfile), "dev:re:"+device.ID)})
		rows = append(rows, []tg.InlineKeyboardButton{btn("🚫 "+l.Text(msgButtonRevoke), "dev:rv:"+device.ID)})
	} else {
		rows = append(rows, []tg.InlineKeyboardButton{btn("📤 "+l.Text(msgButtonReissueProfile), "dev:re:"+device.ID)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(MsgButtonDevices), "dev"), btn("🏠 "+l.Text(msgButtonMenu), "m")})
	return b.String(), keyboard(rows...)
}

// shorten truncates by runes, not bytes: a server name from a subscription can be
// an IDN, and cutting mid-rune yields invalid UTF-8 that Telegram rejects with a
// 400 -- taking the whole screen down with it.
func shorten(value string, length int) string {
	runes := []rune(value)
	if len(runes) <= length {
		return value
	}
	return string(runes[:length])
}

func renderEgressChoice(l Localizer, deviceID, current string, egresses []string) (string, *tg.InlineKeyboardMarkup) {
	text := l.Text(msgEgressChoice, esc(deviceID), esc(current))
	var rows [][]tg.InlineKeyboardButton
	for _, egress := range egresses {
		label := egress
		if egress == current {
			label = "• " + egress + " •"
		}
		rows = append(rows, []tg.InlineKeyboardButton{btn(label, "dev:eg:"+deviceID+":"+egress)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonBack), "dev:c:"+deviceID)})
	return text, keyboard(rows...)
}

// renderConfirm is the second tap every dangerous action requires.
func renderConfirm(l Localizer, question, yesData, noData string) (string, *tg.InlineKeyboardMarkup) {
	return "❓ " + question, keyboard(
		[]tg.InlineKeyboardButton{btn(l.Text(MsgConfirmYes), yesData), btn(l.Text(MsgConfirmNo), noData)},
	)
}

// --- Tunnels ---------------------------------------------------------------

type tunnelEntry struct {
	Tunnel domain.Tunnel
	Health *healthEntry
}

const (
	msgTunnelsTitle      MessageID = "tunnels/title"
	msgButtonTestAll     MessageID = "button/test_all"
	msgAccessTitle       MessageID = "access/title"
	msgAccessEmpty       MessageID = "access/empty"
	msgAccessRestricted  MessageID = "access/restricted"
	msgButtonToTunnel    MessageID = "button/to_tunnel"
	msgTunnelRole        MessageID = "tunnel/role"
	msgTunnelType        MessageID = "tunnel/type"
	msgTunnelState       MessageID = "tunnel/state"
	msgTunnelSource      MessageID = "tunnel/source"
	msgTunnelRoutes      MessageID = "tunnel/routes"
	msgTunnelDNSZones    MessageID = "tunnel/dns_zones"
	msgTunnelOnlyFor     MessageID = "tunnel/only_for"
	msgTunnelAllDevices  MessageID = "tunnel/all_devices"
	msgTunnelHealth      MessageID = "tunnel/health"
	msgSourceHidden      MessageID = "source/hidden"
	msgButtonDisable     MessageID = "button/disable"
	msgButtonEnable      MessageID = "button/enable"
	msgButtonTest        MessageID = "button/test"
	msgButtonProbes      MessageID = "button/probes"
	msgButtonAccess      MessageID = "button/access"
	msgButtonRemoveRoute MessageID = "button/remove_route"
	msgButtonAddRoute    MessageID = "button/add_route"
	msgButtonAddDNSZone  MessageID = "button/add_dns_zone"
	msgButtonRemoveZone  MessageID = "button/remove_zone"
)

func renderTunnels(l Localizer, tunnels []tunnelEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgTunnelsTitle))
	var rows [][]tg.InlineKeyboardButton
	enabled := 0
	for _, entry := range tunnels {
		tunnel := entry.Tunnel
		icon := "⚪️"
		if entry.Health != nil {
			icon = healthIcon(entry.Health.Status)
		}
		if !tunnel.IsEnabled() {
			icon = "⏸"
		} else {
			enabled++
		}
		fmt.Fprintf(&b, "%s <code>%s</code> — %s, %s, %s\n", icon, esc(tunnel.ID), esc(string(tunnel.Role)), esc(string(tunnel.Type)), onOff(l, tunnel.IsEnabled()))
		rows = append(rows, []tg.InlineKeyboardButton{btn(tunnel.ID, "tun:c:"+tunnel.ID)})
	}
	if enabled > 0 {
		rows = append(rows, []tg.InlineKeyboardButton{btn("🩺 "+l.Text(msgButtonTestAll), "tun:ta")})
	}
	rows = append(rows, backRow(l))
	return b.String(), keyboard(rows...)
}

// renderAccess is the allowed_devices editor: which devices may use this egress.
func renderAccess(l Localizer, tunnelID string, devices []string, allowed []string) (string, *tg.InlineKeyboardMarkup) {
	allowedSet := map[string]bool{}
	for _, id := range allowed {
		allowedSet[id] = true
	}
	var b strings.Builder
	b.WriteString(l.Text(msgAccessTitle, esc(tunnelID)))
	if len(allowed) == 0 {
		b.WriteString(l.Text(msgAccessEmpty))
	} else {
		b.WriteString(l.Text(msgAccessRestricted))
	}
	var rows [][]tg.InlineKeyboardButton
	for _, id := range devices {
		mark := "☐"
		if allowedSet[id] {
			mark = "☑️"
		}
		if data := "tun:at:" + tunnelID + ":" + id; len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn(mark+" "+id, data)})
		}
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonToTunnel), "tun:c:"+tunnelID), btn("🏠 "+l.Text(msgButtonMenu), "m")})
	return b.String(), keyboard(rows...)
}

func renderTunnelCard(l Localizer, entry tunnelEntry, now time.Time) (string, *tg.InlineKeyboardMarkup) {
	tunnel := entry.Tunnel
	var b strings.Builder
	fmt.Fprintf(&b, "🚇 <b>%s</b>\n\n", esc(tunnel.ID))
	b.WriteString(l.Text(msgTunnelRole, esc(string(tunnel.Role))))
	b.WriteString(l.Text(msgTunnelType, esc(string(tunnel.Type))))
	b.WriteString(l.Text(msgTunnelState, onOff(l, tunnel.IsEnabled())))
	b.WriteString(l.Text(msgTunnelSource, esc(string(tunnel.Source.Kind)), esc(sourceForDisplay(l, tunnel.Source))))
	if len(tunnel.Routes) > 0 {
		b.WriteString(l.Text(msgTunnelRoutes, esc(strings.Join(tunnel.Routes, ", "))))
	}
	if len(tunnel.DNSZones) > 0 {
		b.WriteString(l.Text(msgTunnelDNSZones, esc(strings.Join(tunnel.DNSZones, ", "))))
	}
	if len(tunnel.AllowedDevices) > 0 {
		b.WriteString(l.Text(msgTunnelOnlyFor, esc(strings.Join(tunnel.AllowedDevices, ", "))))
	} else if tunnel.Role == domain.RoleEgress {
		b.WriteString(l.Text(msgTunnelAllDevices))
	}
	if entry.Health != nil {
		b.WriteString(l.Text(msgTunnelHealth, healthIcon(entry.Health.Status), esc(entry.Health.Reason), formatAge(l, now, entry.Health.CheckedAt)))
	}

	var rows [][]tg.InlineKeyboardButton
	if tunnel.IsEnabled() {
		rows = append(rows, []tg.InlineKeyboardButton{btn("⏸ "+l.Text(msgButtonDisable), "tun:off:"+tunnel.ID), btn("🩺 "+l.Text(msgButtonTest), "tun:t:"+tunnel.ID)})
	} else {
		rows = append(rows, []tg.InlineKeyboardButton{btn("▶️ "+l.Text(msgButtonEnable), "tun:on:"+tunnel.ID), btn("🩺 "+l.Text(msgButtonTest), "tun:t:"+tunnel.ID)})
	}
	probesRow := []tg.InlineKeyboardButton{btn("🩺 "+l.Text(msgButtonProbes), "tun:pr:"+tunnel.ID)}
	if tunnel.Role == domain.RoleEgress {
		probesRow = append(probesRow, btn("👥 "+l.Text(msgButtonAccess), "tun:ac:"+tunnel.ID))
	}
	rows = append(rows, probesRow)
	for _, route := range tunnel.Routes {
		data := "tun:rd:" + tunnel.ID + ":" + route
		if len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn("➖ "+l.Text(msgButtonRemoveRoute, route), data)})
		}
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("➕ "+l.Text(msgButtonAddRoute), "tun:ra:"+tunnel.ID), btn("➕ "+l.Text(msgButtonAddDNSZone), "tun:za:"+tunnel.ID)})
	for _, zone := range tunnel.DNSZones {
		data := "tun:zd:" + tunnel.ID + ":" + zone
		if len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn("➖ "+l.Text(msgButtonRemoveZone, zone), data)})
		}
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonTunnels), "tun"), btn("🏠 "+l.Text(msgButtonMenu), "m")})
	return b.String(), keyboard(rows...)
}

// sourceForDisplay keeps credentials out of the chat: a subscription URL carries a
// token, exactly like it is kept out of revisions.
func sourceForDisplay(l Localizer, source domain.TunnelSource) string {
	if source.Kind == domain.SourceSubscription || source.Kind == domain.SourceXrayURI {
		return l.Text(msgSourceHidden)
	}
	return source.Value
}

// --- Client ACLs ------------------------------------------------------------

type clientACLEntry struct {
	Rule    domain.ClientACL
	Ordinal int
}

const (
	msgACLTitle                   MessageID = "acl/title"
	msgACLIntro                   MessageID = "acl/intro"
	msgACLEmpty                   MessageID = "acl/empty"
	msgButtonAdd                  MessageID = "button/add"
	msgACLAnyDevice               MessageID = "acl/any_device"
	msgACLNewRule                 MessageID = "acl/new_rule"
	msgACLSourceStep              MessageID = "acl/source_step"
	msgACLTargetStep              MessageID = "acl/target_step"
	msgDeployTitle                MessageID = "deploy/title"
	msgDeployNoCurrent            MessageID = "deploy/no_current"
	msgDeployCurrent              MessageID = "deploy/current"
	msgDeployNext                 MessageID = "deploy/next"
	msgDeployRevoked              MessageID = "deploy/revoked"
	msgDeployNoChanges            MessageID = "deploy/no_changes"
	msgDeployChanges              MessageID = "deploy/changes"
	msgDeployChange               MessageID = "deploy/change"
	msgDeployInsuranceExplanation MessageID = "deploy/insurance_explanation"
	msgButtonInsuredDeploy        MessageID = "button/insured_deploy"
	msgButtonImmediateDeploy      MessageID = "button/immediate_deploy"
	msgButtonPreviousRevision     MessageID = "button/previous_revision"
	msgDiffAddTunnel              MessageID = "diff/add_tunnel"
	msgDiffEditTunnel             MessageID = "diff/edit_tunnel"
	msgDiffRemoveTunnel           MessageID = "diff/remove_tunnel"
	msgDiffAddDevice              MessageID = "diff/add_device"
	msgDiffChangeEgress           MessageID = "diff/change_egress"
	msgDiffEditDevice             MessageID = "diff/edit_device"
	msgDiffRemoveDevice           MessageID = "diff/remove_device"
	msgDiffAddACL                 MessageID = "diff/add_acl"
	msgDiffRemoveACL              MessageID = "diff/remove_acl"
	msgDiffHub                    MessageID = "diff/hub"
	msgConfirmWithin              MessageID = "deploy/confirm_within"
	msgCountdown                  MessageID = "deploy/countdown"
	msgCountdownOverdue           MessageID = "deploy/countdown_overdue"
	msgButtonConfirmAnyway        MessageID = "button/confirm_anyway"
	msgButtonRollbackNow          MessageID = "button/rollback_now"
)

func renderClientACLs(l Localizer, entries []clientACLEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgACLTitle))
	b.WriteString(l.Text(msgACLIntro))
	if len(entries) == 0 {
		b.WriteString(l.Text(msgACLEmpty))
	}
	var rows [][]tg.InlineKeyboardButton
	for _, entry := range entries {
		rule := entry.Rule
		fmt.Fprintf(&b, "• <code>%s</code> → <code>%s</code> <code>%s/%d</code>\n",
			esc(rule.Source), esc(rule.Target), esc(string(rule.Protocol)), rule.Port)
		rows = append(rows, []tg.InlineKeyboardButton{btn(
			fmt.Sprintf("➖ %s → %s %s/%d", rule.Source, rule.Target, rule.Protocol, rule.Port),
			fmt.Sprintf("acl:rm:%d", entry.Ordinal),
		)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("➕ "+l.Text(msgButtonAdd), "acl:add")}, backRow(l))
	return b.String(), keyboard(rows...)
}

func renderClientACLSource(l Localizer, devices []string) (string, *tg.InlineKeyboardMarkup) {
	var rows [][]tg.InlineKeyboardButton
	rows = append(rows, []tg.InlineKeyboardButton{btn(l.Text(msgACLAnyDevice), "acl:src:any")})
	for _, id := range devices {
		rows = append(rows, []tg.InlineKeyboardButton{btn(id, "acl:src:"+id)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("✖️ "+l.Text(msgButtonCancel), "acl:x")})
	return l.Text(msgACLNewRule) + l.Text(msgACLSourceStep), keyboard(rows...)
}

func renderClientACLTarget(l Localizer, source string, devices []string) (string, *tg.InlineKeyboardMarkup) {
	var rows [][]tg.InlineKeyboardButton
	for _, id := range devices {
		if id == source {
			continue
		}
		if data := "acl:tgt:" + source + ":" + id; len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn(id, data)})
		}
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("✖️ "+l.Text(msgButtonCancel), "acl:x")})
	return l.Text(msgACLTargetStep, esc(source)), keyboard(rows...)
}

// --- Deploy ----------------------------------------------------------------

type deployView struct {
	Current *domain.DesiredState
	Next    domain.DesiredState
	Revoked []string
	Changes []string
}

func renderDeployPreview(l Localizer, view deployView) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgDeployTitle))
	if view.Current == nil {
		b.WriteString(l.Text(msgDeployNoCurrent))
	} else {
		b.WriteString(l.Text(msgDeployCurrent, esc(view.Current.Revision)))
	}
	tunnels := len(view.Next.Tunnels)
	devices := len(view.Next.Devices)
	b.WriteString(l.Text(msgDeployNext, esc(view.Next.Revision),
		tunnels, plural(l, tunnels, msgPluralTunnelOne, msgPluralTunnelFew, msgPluralTunnelMany),
		devices, plural(l, devices, msgPluralDeviceOne, msgPluralDeviceFew, msgPluralDeviceMany)))
	if len(view.Revoked) > 0 {
		b.WriteString(l.Text(msgDeployRevoked, esc(strings.Join(view.Revoked, ", "))))
	}
	if view.Current != nil && view.Current.Revision == view.Next.Revision {
		b.WriteString(l.Text(msgDeployNoChanges))
	} else if len(view.Changes) > 0 {
		b.WriteString(l.Text(msgDeployChanges))
		for _, change := range view.Changes {
			b.WriteString(l.Text(msgDeployChange, esc(change)))
		}
	}
	b.WriteString(l.Text(msgDeployInsuranceExplanation))

	revision := view.Next.Revision
	rows := [][]tg.InlineKeyboardButton{
		{btn("✅ "+l.Text(msgButtonInsuredDeploy), "dep:arm:"+revision)},
		{btn("⚡ "+l.Text(msgButtonImmediateDeploy), "dep:now:"+revision)},
	}
	if view.Current != nil {
		rows = append(rows, []tg.InlineKeyboardButton{btn("↩️ "+l.Text(msgButtonPreviousRevision), "dep:rb")})
	}
	rows = append(rows, backRow(l))
	return b.String(), keyboard(rows...)
}

// diffStates names what a deploy would change, in operator terms.
func diffStates(l Localizer, current *domain.DesiredState, next domain.DesiredState) []string {
	if current == nil {
		return nil
	}
	var changes []string

	oldTunnels := map[string]domain.Tunnel{}
	for _, tunnel := range current.Tunnels {
		oldTunnels[tunnel.ID] = tunnel
	}
	newTunnels := map[string]domain.Tunnel{}
	for _, tunnel := range next.Tunnels {
		newTunnels[tunnel.ID] = tunnel
		previous, existed := oldTunnels[tunnel.ID]
		switch {
		case !existed:
			changes = append(changes, l.Text(msgDiffAddTunnel, tunnel.ID))
		case !sameJSON(previous, tunnel):
			changes = append(changes, l.Text(msgDiffEditTunnel, tunnel.ID))
		}
	}
	for _, tunnel := range current.Tunnels {
		if _, exists := newTunnels[tunnel.ID]; !exists {
			changes = append(changes, l.Text(msgDiffRemoveTunnel, tunnel.ID))
		}
	}

	oldDevices := map[string]domain.DeployedDevice{}
	for _, device := range current.Devices {
		oldDevices[device.ID] = device
	}
	newDevices := map[string]domain.DeployedDevice{}
	for _, device := range next.Devices {
		newDevices[device.ID] = device
		previous, existed := oldDevices[device.ID]
		switch {
		case !existed:
			changes = append(changes, l.Text(msgDiffAddDevice, device.ID, device.Egress))
		case previous.Egress != device.Egress:
			changes = append(changes, l.Text(msgDiffChangeEgress, device.ID, previous.Egress, device.Egress))
		case previous != device:
			changes = append(changes, l.Text(msgDiffEditDevice, device.ID))
		}
	}
	for _, device := range current.Devices {
		if _, exists := newDevices[device.ID]; !exists {
			changes = append(changes, l.Text(msgDiffRemoveDevice, device.ID))
		}
	}

	oldACLs := map[string]domain.ClientACL{}
	for _, rule := range current.ClientACLs {
		oldACLs[clientACLKey(rule)] = rule
	}
	newACLs := map[string]domain.ClientACL{}
	for _, rule := range next.ClientACLs {
		key := clientACLKey(rule)
		newACLs[key] = rule
		if _, existed := oldACLs[key]; !existed {
			changes = append(changes, l.Text(msgDiffAddACL, clientACLLabel(rule)))
		}
	}
	for _, rule := range current.ClientACLs {
		if _, exists := newACLs[clientACLKey(rule)]; !exists {
			changes = append(changes, l.Text(msgDiffRemoveACL, clientACLLabel(rule)))
		}
	}

	if !sameJSON(current.Hub, next.Hub) {
		changes = append(changes, l.Text(msgDiffHub))
	}
	return changes
}

func clientACLKey(rule domain.ClientACL) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", rule.Source, rule.Target, rule.Protocol, rule.Port)
}

func clientACLLabel(rule domain.ClientACL) string {
	return fmt.Sprintf("%s → %s %s/%d", rule.Source, rule.Target, rule.Protocol, rule.Port)
}

// sameJSON compares via the JSON the revision itself is hashed from, so "changed"
// here means exactly "the revision changed because of it".
func sameJSON(a, b any) bool {
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(left) == string(right)
}

// renderConfirmWithinChoice offers the rollback deadline. The right length depends
// on what is being deployed: a routine egress switch needs a minute, a firewall
// experiment on a remote hub deserves half an hour of grace.
func renderConfirmWithinChoice(l Localizer, revision string) (string, *tg.InlineKeyboardMarkup) {
	text := l.Text(msgConfirmWithin)
	return text, keyboard(
		[]tg.InlineKeyboardButton{
			btn(formatDuration(l, time.Minute), "dep:go:60:"+revision),
			btn(formatDuration(l, 5*time.Minute), "dep:go:300:"+revision),
		},
		[]tg.InlineKeyboardButton{
			btn(formatDuration(l, 15*time.Minute), "dep:go:900:"+revision),
			btn(formatDuration(l, 30*time.Minute), "dep:go:1800:"+revision),
		},
		[]tg.InlineKeyboardButton{btn("✖️ "+l.Text(msgButtonBack), "dep")},
	)
}

func renderCountdown(l Localizer, revision string, left time.Duration) (string, *tg.InlineKeyboardMarkup) {
	text := l.Text(msgCountdown, esc(revision), formatDuration(l, left))
	return text, keyboard([]tg.InlineKeyboardButton{btn("✅ "+l.Text(msgButtonConfirm), "dep:ok"), btn("↩️ "+l.Text(msgButtonRollback), "dep:rb!")})
}

func renderCountdownOverdue(l Localizer, revision string) (string, *tg.InlineKeyboardMarkup) {
	text := l.Text(msgCountdownOverdue, esc(revision))
	return text, keyboard([]tg.InlineKeyboardButton{btn("✅ "+l.Text(msgButtonConfirmAnyway), "dep:ok"), btn("↩️ "+l.Text(msgButtonRollbackNow), "dep:rb!")})
}

// --- Subscriptions ---------------------------------------------------------

type subEntry struct {
	ID       string
	Enabled  bool
	Upstream string
	LastGood bool
	Health   *healthEntry
}

const (
	msgSubsTitle               MessageID = "subscriptions/title"
	msgSubsEmpty               MessageID = "subscriptions/empty"
	msgSubsUpstreamEmpty       MessageID = "subscriptions/upstream_empty"
	msgSubsRefreshSchedule     MessageID = "subscriptions/refresh_schedule"
	msgSubCardUpstreamEmpty    MessageID = "subscription/upstream_empty"
	msgSubCardUpstream         MessageID = "subscription/upstream"
	msgSubCardLastGood         MessageID = "subscription/last_good"
	msgSubCardHealth           MessageID = "subscription/health"
	msgButtonAutoRefresh       MessageID = "button/auto_refresh"
	msgButtonCandidates        MessageID = "button/candidates"
	msgButtonRestoreLastGood   MessageID = "button/restore_last_good"
	msgCandidatesTitle         MessageID = "candidates/title"
	msgCandidatesIntro         MessageID = "candidates/intro"
	msgCandidatesCurrent       MessageID = "candidates/current"
	msgCandidatesPage          MessageID = "candidates/page"
	msgButtonToSubscription    MessageID = "button/to_subscription"
	msgRefreshResultTitle      MessageID = "refresh/result_title"
	msgRefreshResultChosen     MessageID = "refresh/result_chosen"
	msgRefreshResultApply      MessageID = "refresh/result_apply"
	msgRefreshFailureTitle     MessageID = "refresh/failure_title"
	msgRefreshFailureUnchanged MessageID = "refresh/failure_unchanged"
	msgRefreshRejectedSummary  MessageID = "refresh/rejected_summary"
	msgRoutesTitle             MessageID = "routes/title"
	msgRoutesLine              MessageID = "routes/line"
	msgRoutesEmpty             MessageID = "routes/empty"
	msgLogsTitle               MessageID = "logs/title"
	msgLogsUnit                MessageID = "logs/unit"
	msgLogsEmpty               MessageID = "logs/empty"
	msgButtonAgent             MessageID = "button/agent"
	msgButtonBot               MessageID = "button/bot"
	msgButtonSendFile          MessageID = "button/send_file"
)

func renderSubs(l Localizer, entries []subEntry, every time.Duration) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgSubsTitle))
	if len(entries) == 0 {
		b.WriteString(l.Text(msgSubsEmpty))
	}
	var rows [][]tg.InlineKeyboardButton
	for _, entry := range entries {
		upstream := entry.Upstream
		if upstream == "" {
			upstream = l.Text(msgSubsUpstreamEmpty)
		}
		icon := "⚪️"
		if entry.Health != nil {
			icon = healthIcon(entry.Health.Status)
		}
		if !entry.Enabled {
			icon = "⏸"
		}
		fmt.Fprintf(&b, "%s <code>%s</code> — %s\n", icon, esc(entry.ID), esc(upstream))
		rows = append(rows, []tg.InlineKeyboardButton{btn(entry.ID, "sub:c:"+entry.ID)})
	}
	b.WriteString(l.Text(msgSubsRefreshSchedule, formatDuration(l, every)))
	rows = append(rows, backRow(l))
	return b.String(), keyboard(rows...)
}

func renderSubCard(l Localizer, entry subEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	fmt.Fprintf(&b, "📡 <b>%s</b> (%s)\n\n", esc(entry.ID), onOff(l, entry.Enabled))
	if entry.Upstream == "" {
		b.WriteString(l.Text(msgSubCardUpstreamEmpty))
	} else {
		b.WriteString(l.Text(msgSubCardUpstream, esc(entry.Upstream)))
	}
	if entry.LastGood {
		b.WriteString(l.Text(msgSubCardLastGood))
	}
	if entry.Health != nil {
		b.WriteString(l.Text(msgSubCardHealth, healthIcon(entry.Health.Status), esc(entry.Health.Reason)))
	}

	rows := [][]tg.InlineKeyboardButton{
		{btn("🔄 "+l.Text(msgButtonAutoRefresh), "sub:r:"+entry.ID), btn("📋 "+l.Text(msgButtonCandidates), "sub:cand:"+entry.ID)},
	}
	if entry.LastGood {
		rows = append(rows, []tg.InlineKeyboardButton{btn("↩️ "+l.Text(msgButtonRestoreLastGood), "sub:lkg:"+entry.ID)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonSubscriptions), "sub"), btn("🏠 "+l.Text(msgButtonMenu), "m")})
	return b.String(), keyboard(rows...)
}

const candidatesPerPage = 8

// renderCandidates lists what the provider currently offers. Picking one proves it
// in the canary first, so a dead entry costs a wait, never the working upstream.
func renderCandidates(l Localizer, tunnelID string, candidates []domain.ProxyTunnel, page int, current string) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgCandidatesTitle, esc(tunnelID), len(candidates),
		plural(l, len(candidates), msgPluralCandidateOne, msgPluralCandidateFew, msgPluralCandidateMany)))
	b.WriteString(l.Text(msgCandidatesIntro))

	start := page * candidatesPerPage
	end := min(start+candidatesPerPage, len(candidates))
	var rows [][]tg.InlineKeyboardButton
	for index := start; index < end; index++ {
		candidate := candidates[index]
		label := fmt.Sprintf("%s:%d", candidate.Server, candidate.Port)
		if label == current {
			label = l.Text(msgCandidatesCurrent, label)
		}
		rows = append(rows, []tg.InlineKeyboardButton{
			btn(label, fmt.Sprintf("sub:pick:%s:%d", tunnelID, index)),
		})
	}
	var pager []tg.InlineKeyboardButton
	if page > 0 {
		pager = append(pager, btn("⬅️", fmt.Sprintf("sub:cand:%s:%d", tunnelID, page-1)))
	}
	if end < len(candidates) {
		pager = append(pager, btn("➡️", fmt.Sprintf("sub:cand:%s:%d", tunnelID, page+1)))
	}
	if len(pager) > 0 {
		b.WriteString(l.Text(msgCandidatesPage, page+1, (len(candidates)+candidatesPerPage-1)/candidatesPerPage))
		rows = append(rows, pager)
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonToSubscription), "sub:c:"+tunnelID)})
	return b.String(), keyboard(rows...)
}

func renderRefreshResult(l Localizer, tunnelID string, chosen domain.ProxyTunnel, rejectedCount int, agentWarning string) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgRefreshResultTitle, esc(tunnelID)))
	b.WriteString(l.Text(msgRefreshResultChosen, esc(chosen.Server), chosen.Port))
	appendRejectionSummary(l, &b, rejectedCount)
	// No deploy involved: the revision names the link file, not its contents, so
	// the agent re-reads it and restarts the proxy on its next pass by itself.
	b.WriteString(l.Text(msgRefreshResultApply))
	if agentWarning != "" {
		b.WriteString("\n" + agentWarning)
	}
	return b.String(), keyboard(
		[]tg.InlineKeyboardButton{btn("📊 "+l.Text(MsgButtonStatus), "st"), btn("📡 "+l.Text(msgButtonSubscriptions), "sub")},
	)
}

func renderRefreshFailure(l Localizer, tunnelID string, rejectedCount int, failure subscriptionFailureKind) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgRefreshFailureTitle, esc(tunnelID), l.Text(failure.messageID())))
	appendRejectionSummary(l, &b, rejectedCount)
	b.WriteString(l.Text(msgRefreshFailureUnchanged))
	return b.String(), keyboard([]tg.InlineKeyboardButton{btn("📡 "+l.Text(msgButtonSubscriptions), "sub"), btn("🏠 "+l.Text(msgButtonMenu), "m")})
}

func renderSubscriptionFailure(l Localizer, failure subscriptionFailureKind) screen {
	return screen{
		text:   "⚠️ " + l.Text(failure.messageID()),
		markup: keyboard(backRow(l)),
	}
}

func appendRejectionSummary(l Localizer, b *strings.Builder, rejectedCount int) {
	if rejectedCount == 0 {
		return
	}
	b.WriteString(l.Text(msgRefreshRejectedSummary, rejectedCount))
}

// --- Routes ----------------------------------------------------------------

type routeLine struct {
	Destination, Via, Why string
}

func renderRoutes(l Localizer, lines []routeLine) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgRoutesTitle))
	for _, line := range lines {
		b.WriteString(l.Text(msgRoutesLine, esc(line.Destination), esc(line.Via), esc(line.Why)))
	}
	if len(lines) == 0 {
		b.WriteString(l.Text(msgRoutesEmpty))
	}
	return b.String(), keyboard(backRow(l))
}

// --- Logs ------------------------------------------------------------------

func renderLogsMenu(l Localizer, units []linux.UnitStatus) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgLogsTitle))
	rows := [][]tg.InlineKeyboardButton{
		{btn(l.Text(msgButtonAgent), "log:u:vpn-hub-agent.service"), btn(l.Text(msgButtonBot), "log:u:vpn-hub-bot.service")},
	}
	for _, unit := range units {
		b.WriteString(l.Text(msgLogsUnit, esc(unit.Unit), esc(unit.Active), esc(unit.Sub)))
		if unit.Unit == "vpn-hub-agent.service" || unit.Unit == "vpn-hub-bot.service" {
			continue
		}
		if data := "log:u:" + unit.Unit; len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn(unit.Unit, data)})
		}
	}
	rows = append(rows, backRow(l))
	return b.String(), keyboard(rows...)
}

func renderLogTail(l Localizer, unit, tail string) (string, *tg.InlineKeyboardMarkup) {
	// The budget is measured on the escaped content, not the raw journal: esc()
	// turns one `<` into `&lt;`, so trimming the raw text to 3500 could still blow
	// past Telegram's 4096-char cap and lose the whole screen -- exactly when the
	// operator most needs the log.
	content := esc(strings.TrimSpace(tail))
	if content == "" {
		content = l.Text(msgLogsEmpty)
	}
	content = tailWithinBudget(content, 3800)
	text := fmt.Sprintf("📜 <b>%s</b>\n<pre>%s</pre>", esc(unit), content)
	return text, keyboard(
		[]tg.InlineKeyboardButton{btn("🔄 "+l.Text(msgButtonRefresh), "log:u:"+unit), btn("📄 "+l.Text(msgButtonSendFile), "log:f:"+unit)},
		[]tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonLogs), "log"), btn("🏠 "+l.Text(msgButtonMenu), "m")},
	)
}

// tailWithinBudget keeps the last runes of an already-escaped string under a char
// budget, dropping whole leading lines. A newline never falls inside an HTML
// entity esc() produces, so cutting at one cannot split an entity and yield markup
// Telegram rejects.
func tailWithinBudget(escaped string, limit int) string {
	for len([]rune(escaped)) > limit {
		cut := strings.IndexByte(escaped, '\n')
		if cut < 0 {
			break
		}
		escaped = escaped[cut+1:]
	}
	// A single line longer than the budget is pathological for journal output; cut
	// it on a rune boundary. A leading entity fragment renders literally rather
	// than breaking the message, and the result is always valid UTF-8.
	if runes := []rune(escaped); len(runes) > limit {
		escaped = string(runes[len(runes)-limit:])
	}
	return escaped
}

// --- Host ------------------------------------------------------------------

type hostView struct {
	Snapshot linux.HostSnapshot
	Err      string
	Units    []linux.UnitStatus
}

const (
	msgHostTitle            MessageID = "host/title"
	msgHostError            MessageID = "host/error"
	msgHostUptime           MessageID = "host/uptime"
	msgHostLoad             MessageID = "host/load"
	msgHostDisk             MessageID = "host/disk"
	msgHostUnits            MessageID = "host/units"
	msgHostUnit             MessageID = "host/unit"
	msgHostRestarts         MessageID = "host/restarts"
	msgButtonRestartAgent   MessageID = "button/restart_agent"
	msgButtonEndpoint       MessageID = "button/endpoint"
	msgButtonDNS            MessageID = "button/dns"
	msgHubTitle             MessageID = "hub/title"
	msgHubEndpoint          MessageID = "hub/endpoint"
	msgHubClientNetwork     MessageID = "hub/client_network"
	msgHubDNS               MessageID = "hub/dns"
	msgHubPublicKey         MessageID = "hub/public_key"
	msgHubAWGParameters     MessageID = "hub/awg_parameters"
	msgHubAWGParameter      MessageID = "hub/awg_parameter"
	msgHubWarning           MessageID = "hub/warning"
	msgButtonClientNetwork  MessageID = "button/client_network"
	msgButtonAWGParameter   MessageID = "button/awg_parameter"
	msgButtonRotateHubKey   MessageID = "button/rotate_hub_key"
	msgButtonExportConfig   MessageID = "button/export_config"
	msgProbesTitle          MessageID = "probes/title"
	msgProbesIntro          MessageID = "probes/intro"
	msgProbesUnset          MessageID = "probes/unset"
	msgProbesValue          MessageID = "probes/value"
	msgSettingsTitle        MessageID = "settings/title"
	msgSettingsIntervals    MessageID = "settings/intervals"
	msgSettingsExplanation  MessageID = "settings/explanation"
	msgCategoryRollback     MessageID = "settings/category/rollback"
	msgCategoryAgentError   MessageID = "settings/category/agent_error"
	msgCategoryConverge     MessageID = "settings/category/converge"
	msgCategoryHealth       MessageID = "settings/category/health"
	msgCategoryDrift        MessageID = "settings/category/drift"
	msgCategorySubscription MessageID = "settings/category/subscription"
	msgCategoryOutOfBand    MessageID = "settings/category/out_of_band"
)

func renderHost(l Localizer, view hostView) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgHostTitle))
	if view.Err != "" {
		b.WriteString(l.Text(msgHostError, esc(view.Err)))
	} else {
		b.WriteString(l.Text(msgHostUptime, formatDuration(l, view.Snapshot.Uptime)))
		b.WriteString(l.Text(msgHostLoad, esc(view.Snapshot.Load1), esc(view.Snapshot.Load5), esc(view.Snapshot.Load15)))
		b.WriteString(l.Text(msgHostDisk, formatGiB(l, view.Snapshot.DiskFree), formatGiB(l, view.Snapshot.DiskTotal)))
	}
	if len(view.Units) > 0 {
		b.WriteString(l.Text(msgHostUnits))
		for _, unit := range view.Units {
			icon := "🔴"
			if unit.Active == "active" {
				icon = "🟢"
			}
			b.WriteString(l.Text(msgHostUnit, icon, esc(unit.Unit), esc(unit.Active), esc(unit.Sub)))
			if unit.Restarts > 0 {
				b.WriteString(l.Text(msgHostRestarts, unit.Restarts))
			}
			b.WriteString("\n")
		}
	}
	return b.String(), keyboard(
		[]tg.InlineKeyboardButton{btn("🔄 "+l.Text(msgButtonRefresh), "host"), btn("🔁 "+l.Text(msgButtonRestartAgent), "host:ra")},
		backRow(l),
	)
}

// --- Hub -------------------------------------------------------------------

func renderHub(l Localizer, hub domain.Hub) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgHubTitle))
	b.WriteString(l.Text(msgHubEndpoint, esc(hub.Endpoint)))
	b.WriteString(l.Text(msgHubClientNetwork, esc(hub.ClientCIDR)))
	b.WriteString(l.Text(msgHubDNS, esc(hub.DNSAddress)))
	b.WriteString(l.Text(msgHubPublicKey, esc(shorten(hub.ServerPublicKey, 12))))
	if len(hub.AWGInterface) > 0 {
		b.WriteString(l.Text(msgHubAWGParameters))
		keys := make([]string, 0, len(hub.AWGInterface))
		for key := range hub.AWGInterface {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			name, _ := domain.CanonicalAWGParameter(key)
			b.WriteString(l.Text(msgHubAWGParameter, esc(name), esc(hub.AWGInterface[key])))
		}
	}
	b.WriteString(l.Text(msgHubWarning))

	rows := [][]tg.InlineKeyboardButton{
		{btn("✏️ "+l.Text(msgButtonEndpoint), "hub:e:endpoint"), btn("✏️ "+l.Text(msgButtonDNS), "hub:e:dns_address")},
		{btn("✏️ "+l.Text(msgButtonClientNetwork), "hub:e:client_cidr"), btn("➕ "+l.Text(msgButtonAWGParameter), "hub:aa")},
	}
	if len(hub.AWGInterface) > 0 {
		keys := make([]string, 0, len(hub.AWGInterface))
		for key := range hub.AWGInterface {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			name, _ := domain.CanonicalAWGParameter(key)
			if data := "hub:ad:" + key; len(data) <= 64 {
				rows = append(rows, []tg.InlineKeyboardButton{btn("➖ "+name, data)})
			}
		}
	}
	rows = append(rows,
		[]tg.InlineKeyboardButton{btn("🔑 "+l.Text(msgButtonRotateHubKey), "hub:rk"), btn("📦 "+l.Text(msgButtonExportConfig), "hub:dl")},
		backRow(l))
	return b.String(), keyboard(rows...)
}

// --- Tunnel probes ---------------------------------------------------------

var probeKinds = []struct {
	Key, Field, Title, Example string
}{
	{"tcp", "tcp_address", "TCP", "10.20.0.1:443"},
	{"https", "https_url", "HTTPS", "https://1.1.1.1/cdn-cgi/trace"},
	{"dns", "dns_name", "DNS", "host.corp.internal"},
}

func renderProbes(l Localizer, tunnelID string, health domain.HealthCheck) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgProbesTitle, esc(tunnelID)))
	b.WriteString(l.Text(msgProbesIntro))
	var rows [][]tg.InlineKeyboardButton
	for _, kind := range probeKinds {
		value := probeValue(health, kind.Key)
		if value == "" {
			b.WriteString(l.Text(msgProbesUnset, kind.Title))
			rows = append(rows, []tg.InlineKeyboardButton{btn("➕ "+kind.Title, "tun:ps:"+tunnelID+":"+kind.Key)})
			continue
		}
		b.WriteString(l.Text(msgProbesValue, kind.Title, esc(value)))
		rows = append(rows, []tg.InlineKeyboardButton{
			btn("✏️ "+kind.Title, "tun:ps:"+tunnelID+":"+kind.Key),
			btn("➖ "+kind.Title, "tun:pd:"+tunnelID+":"+kind.Key),
		})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ "+l.Text(msgButtonToTunnel), "tun:c:"+tunnelID), btn("🏠 "+l.Text(msgButtonMenu), "m")})
	return b.String(), keyboard(rows...)
}

// --- Settings --------------------------------------------------------------

var notificationCategories = []struct {
	Key     string
	TitleID MessageID
}{
	{"rollback", msgCategoryRollback},
	{"agent-error", msgCategoryAgentError},
	{"converge", msgCategoryConverge},
	{"health", msgCategoryHealth},
	{"drift", msgCategoryDrift},
	{"subscription", msgCategorySubscription},
	{"oob", msgCategoryOutOfBand},
}

func renderSettings(l Localizer, enabled map[string]bool, notifications Notifications) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString(l.Text(msgSettingsTitle))
	b.WriteString(l.Text(msgSettingsIntervals,
		formatDuration(l, notifications.HealthInterval), formatDuration(l, notifications.DriftInterval), formatDuration(l, notifications.SubscriptionRefresh)))
	var rows [][]tg.InlineKeyboardButton
	for _, category := range notificationCategories {
		mark := "🔕"
		if enabled[category.Key] {
			mark = "🔔"
		}
		rows = append(rows, []tg.InlineKeyboardButton{btn(mark+" "+l.Text(category.TitleID), "set:t:"+category.Key)})
	}
	b.WriteString(l.Text(msgSettingsExplanation))
	rows = append(rows, backRow(l))
	return b.String(), keyboard(rows...)
}
