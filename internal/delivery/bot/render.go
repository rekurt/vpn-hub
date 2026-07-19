package bot

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

// Everything user-visible is rendered here and nowhere else, in Russian, as
// Telegram HTML. The functions are pure -- data in, text and keyboard out -- so the
// golden tests can hold every screen still.

func esc(value string) string { return html.EscapeString(value) }

func btn(text, data string) tg.InlineKeyboardButton {
	return tg.InlineKeyboardButton{Text: text, CallbackData: data}
}

func keyboard(rows ...[]tg.InlineKeyboardButton) *tg.InlineKeyboardMarkup {
	return &tg.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// ruDuration says how long compactly: "2ч 5м", "3м 20с", "45с". Zero components
// are dropped -- "5м", not "5м 0с".
func ruDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	switch {
	case hours >= 48 && hours%24 == 0:
		return fmt.Sprintf("%dд", hours/24)
	case hours >= 48:
		return fmt.Sprintf("%dд %dч", hours/24, hours%24)
	case hours > 0 && minutes == 0:
		return fmt.Sprintf("%dч", hours)
	case hours > 0:
		return fmt.Sprintf("%dч %dм", hours, minutes)
	case minutes > 0 && seconds == 0:
		return fmt.Sprintf("%dм", minutes)
	case minutes > 0:
		return fmt.Sprintf("%dм %dс", minutes, seconds)
	default:
		return fmt.Sprintf("%dс", seconds)
	}
}

// ruPlural picks the Russian plural form: one, few (2-4), many.
func ruPlural(count int, one, few, many string) string {
	tail, hundred := count%10, count%100
	switch {
	case hundred >= 11 && hundred <= 14:
		return many
	case tail == 1:
		return one
	case tail >= 2 && tail <= 4:
		return few
	default:
		return many
	}
}

// ruAge says how long ago something happened.
func ruAge(now, then time.Time) string {
	if then.IsZero() {
		return "никогда"
	}
	age := now.Sub(then)
	if age < time.Minute {
		return "только что"
	}
	return ruDuration(age) + " назад"
}

func gib(bytes uint64) string {
	return fmt.Sprintf("%.1f ГиБ", float64(bytes)/(1<<30))
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

func onOff(enabled bool) string {
	if enabled {
		return "вкл"
	}
	return "выкл"
}

// --- Main menu -------------------------------------------------------------

func renderMain() (string, *tg.InlineKeyboardMarkup) {
	text := "🏠 <b>vpn-hub</b>\nУправление хабом. Выберите раздел:"
	return text, keyboard(
		[]tg.InlineKeyboardButton{btn("📊 Статус", "st"), btn("📱 Устройства", "dev")},
		[]tg.InlineKeyboardButton{btn("🚇 Туннели", "tun"), btn("📡 Подписки", "sub")},
		[]tg.InlineKeyboardButton{btn("🚀 Деплой", "dep"), btn("🗺 Маршруты", "rt")},
		[]tg.InlineKeyboardButton{btn("📜 Логи", "log"), btn("🖥 Хост", "host")},
		[]tg.InlineKeyboardButton{btn("🔔 Настройки", "set")},
	)
}

var backRow = []tg.InlineKeyboardButton{btn("🏠 Меню", "m")}

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
}

func renderStatus(view statusView) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("📊 <b>Статус</b>\n\n")

	switch {
	case view.StateErr != "":
		fmt.Fprintf(&b, "Ревизия: ⚠️ %s\n", esc(view.StateErr))
	case view.State == nil:
		b.WriteString("Ревизия: ещё не развёрнута\n")
	default:
		fmt.Fprintf(&b, "Ревизия: <code>%s</code> (создана %s)\n", esc(view.State.Revision), ruAge(view.Now, view.State.GeneratedAt))
		fmt.Fprintf(&b, "Туннелей: %d, устройств: %d\n", len(view.State.Tunnels), len(view.State.Devices))
	}

	if view.Pending != nil {
		left := view.Pending.Deadline.Sub(view.Now)
		if left > 0 {
			fmt.Fprintf(&b, "\n⏳ <b>Ждёт подтверждения</b>: ревизия <code>%s</code>, осталось %s\n", esc(view.Pending.Revision), ruDuration(left))
		} else {
			fmt.Fprintf(&b, "\n⛔ Ревизия <code>%s</code> просрочена: агент откатит её на ближайшем проходе\n", esc(view.Pending.Revision))
		}
	}

	b.WriteString("\n")
	switch {
	case view.AgentErr != "":
		fmt.Fprintf(&b, "Агент: ⚠️ %s\n", esc(view.AgentErr))
	case view.Agent != nil:
		icon := "🔴"
		if view.Agent.Active == "active" {
			icon = "🟢"
		}
		fmt.Fprintf(&b, "Агент: %s %s (%s), рестартов: %d\n", icon, esc(view.Agent.Active), esc(view.Agent.Sub), view.Agent.Restarts)
	}

	switch {
	case view.DriftErr != "":
		fmt.Fprintf(&b, "Дрейф: ⚠️ %s\n", esc(view.DriftErr))
	case len(view.Drift) == 0:
		b.WriteString("Дрейф: ✅ хост сошёлся с ревизией\n")
	default:
		fmt.Fprintf(&b, "Дрейф: ⚠️ %d %s:\n", len(view.Drift), ruPlural(len(view.Drift), "расхождение", "расхождения", "расхождений"))
		for index, operation := range view.Drift {
			if index == 8 {
				fmt.Fprintf(&b, " • … и ещё %d\n", len(view.Drift)-index)
				break
			}
			fmt.Fprintf(&b, " • <code>%s</code>\n", esc(operation.String()))
		}
	}

	if len(view.Health) > 0 {
		fmt.Fprintf(&b, "\n<b>Здоровье туннелей</b> (проба раз в %s):\n", ruDuration(view.HealthEvery))
		for _, entry := range view.Health {
			fmt.Fprintf(&b, "%s <code>%s</code> — %s (%s)\n", healthIcon(entry.Status), esc(entry.ID), esc(entry.Reason), ruAge(view.Now, entry.CheckedAt))
		}
	}

	rows := [][]tg.InlineKeyboardButton{{btn("🔄 Обновить", "st"), btn("🏠 Меню", "m")}}
	if view.Pending != nil {
		rows = append([][]tg.InlineKeyboardButton{{btn("✅ Подтвердить", "dep:ok"), btn("↩️ Откатить", "dep:rb!")}}, rows...)
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
}

func renderDevices(devices []deviceEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("📱 <b>Устройства</b>\n\n")
	if len(devices) == 0 {
		b.WriteString("Пока ни одного устройства.\n")
	}
	for _, device := range devices {
		mark := ""
		if device.Revoked {
			mark = " 🚫 отозвано"
		}
		fmt.Fprintf(&b, "• <code>%s</code> — %s → %s%s\n", esc(device.ID), esc(device.Address), esc(device.Egress), mark)
	}

	var rows [][]tg.InlineKeyboardButton
	for i := 0; i < len(devices); i += 2 {
		row := []tg.InlineKeyboardButton{btn(devices[i].ID, "dev:c:"+devices[i].ID)}
		if i+1 < len(devices) {
			row = append(row, btn(devices[i+1].ID, "dev:c:"+devices[i+1].ID))
		}
		rows = append(rows, row)
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("➕ Добавить устройство", "dev:add")}, backRow)
	return b.String(), keyboard(rows...)
}

func renderDeviceCard(device deviceEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	fmt.Fprintf(&b, "📱 <b>%s</b>\n\n", esc(device.ID))
	fmt.Fprintf(&b, "Адрес: <code>%s</code>\n", esc(device.Address))
	fmt.Fprintf(&b, "Egress: <code>%s</code>\n", esc(device.Egress))
	fmt.Fprintf(&b, "Ключ: <code>%s…</code>\n", esc(shorten(device.PublicKey, 12)))
	if device.Revoked {
		b.WriteString("\n🚫 <b>Отозвано</b>: устройство исключается из ревизии при деплое.\nПеревыпуск профиля снимет отзыв.\n")
	}
	rows := [][]tg.InlineKeyboardButton{
		{btn("🔀 Сменить egress", "dev:eg:"+device.ID)},
		{btn("📤 Перевыпустить профиль", "dev:re:"+device.ID)},
	}
	if !device.Revoked {
		rows = append(rows, []tg.InlineKeyboardButton{btn("🚫 Отозвать", "dev:rv:"+device.ID)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ Устройства", "dev"), btn("🏠 Меню", "m")})
	return b.String(), keyboard(rows...)
}

func shorten(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length]
}

func renderEgressChoice(deviceID, current string, egresses []string) (string, *tg.InlineKeyboardMarkup) {
	text := fmt.Sprintf("🔀 Через что выпускать <b>%s</b> в интернет?\nСейчас: <code>%s</code>", esc(deviceID), esc(current))
	var rows [][]tg.InlineKeyboardButton
	for _, egress := range egresses {
		label := egress
		if egress == current {
			label = "• " + egress + " •"
		}
		rows = append(rows, []tg.InlineKeyboardButton{btn(label, "dev:eg:"+deviceID+":"+egress)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ Назад", "dev:c:"+deviceID)})
	return text, keyboard(rows...)
}

// renderConfirm is the second tap every dangerous action requires.
func renderConfirm(question, yesData, noData string) (string, *tg.InlineKeyboardMarkup) {
	return "❓ " + question, keyboard(
		[]tg.InlineKeyboardButton{btn("Да", yesData), btn("Нет", noData)},
	)
}

// --- Tunnels ---------------------------------------------------------------

type tunnelEntry struct {
	Tunnel domain.Tunnel
	Health *healthEntry
}

func renderTunnels(tunnels []tunnelEntry) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("🚇 <b>Туннели</b>\n\n")
	var rows [][]tg.InlineKeyboardButton
	for _, entry := range tunnels {
		tunnel := entry.Tunnel
		icon := "⚪️"
		if entry.Health != nil {
			icon = healthIcon(entry.Health.Status)
		}
		if !tunnel.IsEnabled() {
			icon = "⏸"
		}
		fmt.Fprintf(&b, "%s <code>%s</code> — %s, %s, %s\n", icon, esc(tunnel.ID), esc(string(tunnel.Role)), esc(string(tunnel.Type)), onOff(tunnel.IsEnabled()))
		rows = append(rows, []tg.InlineKeyboardButton{btn(tunnel.ID, "tun:c:"+tunnel.ID)})
	}
	rows = append(rows, backRow)
	return b.String(), keyboard(rows...)
}

func renderTunnelCard(entry tunnelEntry, now time.Time) (string, *tg.InlineKeyboardMarkup) {
	tunnel := entry.Tunnel
	var b strings.Builder
	fmt.Fprintf(&b, "🚇 <b>%s</b>\n\n", esc(tunnel.ID))
	fmt.Fprintf(&b, "Роль: %s\nТип: %s\nСостояние: %s\n", esc(string(tunnel.Role)), esc(string(tunnel.Type)), onOff(tunnel.IsEnabled()))
	fmt.Fprintf(&b, "Источник: %s <code>%s</code>\n", esc(string(tunnel.Source.Kind)), esc(sourceForDisplay(tunnel.Source)))
	if len(tunnel.Routes) > 0 {
		fmt.Fprintf(&b, "Маршруты: <code>%s</code>\n", esc(strings.Join(tunnel.Routes, ", ")))
	}
	if len(tunnel.DNSZones) > 0 {
		fmt.Fprintf(&b, "DNS-зоны: <code>%s</code>\n", esc(strings.Join(tunnel.DNSZones, ", ")))
	}
	if len(tunnel.AllowedDevices) > 0 {
		fmt.Fprintf(&b, "Только для: <code>%s</code>\n", esc(strings.Join(tunnel.AllowedDevices, ", ")))
	}
	if entry.Health != nil {
		fmt.Fprintf(&b, "\n%s %s (%s)\n", healthIcon(entry.Health.Status), esc(entry.Health.Reason), ruAge(now, entry.Health.CheckedAt))
	}

	var rows [][]tg.InlineKeyboardButton
	if tunnel.IsEnabled() {
		rows = append(rows, []tg.InlineKeyboardButton{btn("⏸ Выключить", "tun:off:"+tunnel.ID), btn("🩺 Проверить", "tun:t:"+tunnel.ID)})
	} else {
		rows = append(rows, []tg.InlineKeyboardButton{btn("▶️ Включить", "tun:on:"+tunnel.ID), btn("🩺 Проверить", "tun:t:"+tunnel.ID)})
	}
	for _, route := range tunnel.Routes {
		data := "tun:rd:" + tunnel.ID + ":" + route
		if len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn("➖ маршрут "+route, data)})
		}
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("➕ Маршрут", "tun:ra:"+tunnel.ID), btn("➕ DNS-зона", "tun:za:"+tunnel.ID)})
	for _, zone := range tunnel.DNSZones {
		data := "tun:zd:" + tunnel.ID + ":" + zone
		if len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn("➖ зона "+zone, data)})
		}
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("⬅️ Туннели", "tun"), btn("🏠 Меню", "m")})
	return b.String(), keyboard(rows...)
}

// sourceForDisplay keeps credentials out of the chat: a subscription URL carries a
// token, exactly like it is kept out of revisions.
func sourceForDisplay(source domain.TunnelSource) string {
	if source.Kind == domain.SourceSubscription || source.Kind == domain.SourceXrayURI {
		return "[скрыто]"
	}
	return source.Value
}

// --- Deploy ----------------------------------------------------------------

type deployView struct {
	Current *domain.DesiredState
	Next    domain.DesiredState
	Revoked []string
	Changes []string
}

func renderDeployPreview(view deployView) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("🚀 <b>Деплой</b>\n\n")
	if view.Current == nil {
		b.WriteString("Активной ревизии нет: это первый деплой, откатывать будет некуда.\n")
	} else {
		fmt.Fprintf(&b, "Активная ревизия: <code>%s</code>\n", esc(view.Current.Revision))
	}
	fmt.Fprintf(&b, "Новая ревизия: <code>%s</code> (%d туннелей, %d устройств)\n", esc(view.Next.Revision), len(view.Next.Tunnels), len(view.Next.Devices))
	if len(view.Revoked) > 0 {
		fmt.Fprintf(&b, "Исключены отозванные: <code>%s</code>\n", esc(strings.Join(view.Revoked, ", ")))
	}
	if view.Current != nil && view.Current.Revision == view.Next.Revision {
		b.WriteString("\n✅ Конфигурация не отличается от активной ревизии; деплой ничего не изменит.\n")
	} else if len(view.Changes) > 0 {
		b.WriteString("\n<b>Изменения:</b>\n")
		for _, change := range view.Changes {
			fmt.Fprintf(&b, " • %s\n", esc(change))
		}
	}
	b.WriteString("\nСо страховкой агент вернёт предыдущую ревизию сам, если не подтвердить за 5 минут — даже если новая ревизия отрежет доступ.")

	revision := view.Next.Revision
	rows := [][]tg.InlineKeyboardButton{
		{btn("✅ Применить (страховка 5 мин)", "dep:go:300:"+revision)},
		{btn("⚡ Применить без страховки", "dep:now:"+revision)},
	}
	if view.Current != nil {
		rows = append(rows, []tg.InlineKeyboardButton{btn("↩️ Вернуть предыдущую ревизию", "dep:rb")})
	}
	rows = append(rows, backRow)
	return b.String(), keyboard(rows...)
}

// diffStates names what a deploy would change, in operator terms.
func diffStates(current *domain.DesiredState, next domain.DesiredState) []string {
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
			changes = append(changes, "➕ туннель "+tunnel.ID)
		case !sameJSON(previous, tunnel):
			changes = append(changes, "✏️ туннель "+tunnel.ID)
		}
	}
	for _, tunnel := range current.Tunnels {
		if _, exists := newTunnels[tunnel.ID]; !exists {
			changes = append(changes, "➖ туннель "+tunnel.ID)
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
			changes = append(changes, "➕ устройство "+device.ID+" → "+device.Egress)
		case previous.Egress != device.Egress:
			changes = append(changes, "🔀 "+device.ID+": "+previous.Egress+" → "+device.Egress)
		case previous != device:
			changes = append(changes, "✏️ устройство "+device.ID)
		}
	}
	for _, device := range current.Devices {
		if _, exists := newDevices[device.ID]; !exists {
			changes = append(changes, "➖ устройство "+device.ID)
		}
	}

	if !sameJSON(current.Hub, next.Hub) {
		changes = append(changes, "✏️ параметры хаба")
	}
	return changes
}

// sameJSON compares via the JSON the revision itself is hashed from, so "changed"
// here means exactly "the revision changed because of it".
func sameJSON(a, b any) bool {
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(left) == string(right)
}

func renderCountdown(revision string, left time.Duration) (string, *tg.InlineKeyboardMarkup) {
	text := fmt.Sprintf("⏳ Ревизия <code>%s</code> применена и ждёт подтверждения.\nОсталось: <b>%s</b>\n\nБез подтверждения агент вернёт предыдущую ревизию.", esc(revision), ruDuration(left))
	return text, keyboard([]tg.InlineKeyboardButton{btn("✅ Подтвердить", "dep:ok"), btn("↩️ Откатить", "dep:rb!")})
}

func renderCountdownOverdue(revision string) (string, *tg.InlineKeyboardMarkup) {
	text := fmt.Sprintf("⛔ Ревизию <code>%s</code> не подтвердили вовремя.\nАгент вернёт предыдущую на ближайшем проходе; если он не работает, откат не случится — проверьте /host.", esc(revision))
	return text, keyboard([]tg.InlineKeyboardButton{btn("✅ Всё же подтвердить", "dep:ok"), btn("↩️ Откатить сейчас", "dep:rb!")})
}

// --- Subscriptions ---------------------------------------------------------

type subEntry struct {
	ID          string
	Enabled     bool
	Upstream    string
	HasLastGood bool
}

func renderSubs(entries []subEntry, every time.Duration) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("📡 <b>Подписки</b>\n\n")
	if len(entries) == 0 {
		b.WriteString("Туннелей с подпиской нет.\n")
	}
	var rows [][]tg.InlineKeyboardButton
	for _, entry := range entries {
		upstream := entry.Upstream
		if upstream == "" {
			upstream = "upstream ещё не выбран"
		}
		fmt.Fprintf(&b, "• <code>%s</code> (%s) — %s", esc(entry.ID), onOff(entry.Enabled), esc(upstream))
		if entry.HasLastGood {
			b.WriteString(", есть last-known-good")
		}
		b.WriteString("\n")
		rows = append(rows, []tg.InlineKeyboardButton{btn("🔄 Обновить "+entry.ID, "sub:r:"+entry.ID)})
	}
	fmt.Fprintf(&b, "\nАвтообновление: раз в %s, кандидат сперва доказывает работоспособность в изолированном namespace.", ruDuration(every))
	rows = append(rows, backRow)
	return b.String(), keyboard(rows...)
}

func renderRefreshResult(tunnelID string, chosen domain.ProxyTunnel, rejected []string, agentWarning string) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	fmt.Fprintf(&b, "📡 <b>%s</b>: выбран новый upstream\n\n", esc(tunnelID))
	fmt.Fprintf(&b, "✅ <code>%s:%d</code> — доказал работоспособность\n", esc(chosen.Server), chosen.Port)
	appendRejections(&b, rejected)
	// No deploy involved: the revision names the link file, not its contents, so
	// the agent re-reads it and restarts the proxy on its next pass by itself.
	b.WriteString("\nАгент подхватит новый upstream на ближайшем проходе (обычно в течение минуты).")
	if agentWarning != "" {
		b.WriteString("\n" + agentWarning)
	}
	return b.String(), keyboard(
		[]tg.InlineKeyboardButton{btn("📊 Статус", "st"), btn("📡 Подписки", "sub")},
	)
}

func renderRefreshFailure(tunnelID string, rejected []string, message string) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	fmt.Fprintf(&b, "📡 <b>%s</b>: обновление не удалось\n\n⚠️ %s\n", esc(tunnelID), esc(message))
	appendRejections(&b, rejected)
	b.WriteString("\nДействующий upstream не тронут.")
	return b.String(), keyboard([]tg.InlineKeyboardButton{btn("📡 Подписки", "sub"), btn("🏠 Меню", "m")})
}

func appendRejections(b *strings.Builder, rejected []string) {
	if len(rejected) == 0 {
		return
	}
	fmt.Fprintf(b, "\nОтклонены (%d):\n", len(rejected))
	for index, reason := range rejected {
		if index == 10 {
			fmt.Fprintf(b, " • … и ещё %d\n", len(rejected)-index)
			break
		}
		fmt.Fprintf(b, " • <code>%s</code>\n", esc(shorten(reason, 120)))
	}
}

// --- Routes ----------------------------------------------------------------

type routeLine struct {
	Destination, Via, Why string
}

func renderRoutes(lines []routeLine) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("🗺 <b>Маршруты</b>: куда → через что\n\n")
	for _, line := range lines {
		fmt.Fprintf(&b, "• <code>%s</code> → <code>%s</code> — %s\n", esc(line.Destination), esc(line.Via), esc(line.Why))
	}
	if len(lines) == 0 {
		b.WriteString("Ревизия пуста.\n")
	}
	return b.String(), keyboard(backRow)
}

// --- Logs ------------------------------------------------------------------

func renderLogsMenu(units []linux.UnitStatus) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("📜 <b>Логи</b>\n\nЮниты vpn-hub на хосте:\n")
	rows := [][]tg.InlineKeyboardButton{
		{btn("Агент", "log:u:vpn-hub-agent.service"), btn("Бот", "log:u:vpn-hub-bot.service")},
	}
	for _, unit := range units {
		fmt.Fprintf(&b, "• <code>%s</code> — %s (%s)\n", esc(unit.Unit), esc(unit.Active), esc(unit.Sub))
		if unit.Unit == "vpn-hub-agent.service" || unit.Unit == "vpn-hub-bot.service" {
			continue
		}
		if data := "log:u:" + unit.Unit; len(data) <= 64 {
			rows = append(rows, []tg.InlineKeyboardButton{btn(unit.Unit, data)})
		}
	}
	rows = append(rows, backRow)
	return b.String(), keyboard(rows...)
}

func renderLogTail(unit, tail string) (string, *tg.InlineKeyboardMarkup) {
	const limit = 3500
	trimmed := strings.TrimSpace(tail)
	if len(trimmed) > limit {
		if cut := strings.IndexByte(trimmed[len(trimmed)-limit:], '\n'); cut >= 0 {
			trimmed = trimmed[len(trimmed)-limit+cut+1:]
		} else {
			trimmed = trimmed[len(trimmed)-limit:]
		}
	}
	if trimmed == "" {
		trimmed = "(журнал пуст)"
	}
	text := fmt.Sprintf("📜 <b>%s</b>\n<pre>%s</pre>", esc(unit), esc(trimmed))
	return text, keyboard(
		[]tg.InlineKeyboardButton{btn("🔄 Обновить", "log:u:"+unit), btn("📄 Файлом (500)", "log:f:"+unit)},
		[]tg.InlineKeyboardButton{btn("⬅️ Логи", "log"), btn("🏠 Меню", "m")},
	)
}

// --- Host ------------------------------------------------------------------

type hostView struct {
	Snapshot linux.HostSnapshot
	Err      string
	Units    []linux.UnitStatus
}

func renderHost(view hostView) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("🖥 <b>Хост</b>\n\n")
	if view.Err != "" {
		fmt.Fprintf(&b, "⚠️ %s\n", esc(view.Err))
	} else {
		fmt.Fprintf(&b, "Аптайм: %s\n", ruDuration(view.Snapshot.Uptime))
		fmt.Fprintf(&b, "Загрузка: %s %s %s\n", esc(view.Snapshot.Load1), esc(view.Snapshot.Load5), esc(view.Snapshot.Load15))
		fmt.Fprintf(&b, "Диск /: свободно %s из %s\n", gib(view.Snapshot.DiskFree), gib(view.Snapshot.DiskTotal))
	}
	if len(view.Units) > 0 {
		b.WriteString("\n<b>Юниты:</b>\n")
		for _, unit := range view.Units {
			icon := "🔴"
			if unit.Active == "active" {
				icon = "🟢"
			}
			fmt.Fprintf(&b, "%s <code>%s</code> — %s (%s)", icon, esc(unit.Unit), esc(unit.Active), esc(unit.Sub))
			if unit.Restarts > 0 {
				fmt.Fprintf(&b, ", рестартов: %d", unit.Restarts)
			}
			b.WriteString("\n")
		}
	}
	return b.String(), keyboard(
		[]tg.InlineKeyboardButton{btn("🔄 Обновить", "host"), btn("🔁 Перезапустить агента", "host:ra")},
		backRow,
	)
}

// --- Settings --------------------------------------------------------------

var notificationCategories = []struct {
	Key, Title string
}{
	{"rollback", "Автооткаты и деплой"},
	{"agent-error", "Ошибки агента"},
	{"converge", "Сходимость (инфо)"},
	{"health", "Здоровье туннелей"},
	{"drift", "Дрейф хоста"},
	{"subscription", "Итоги обновления подписок"},
	{"oob", "Изменения мимо бота"},
}

func renderSettings(enabled map[string]bool, notifications Notifications) (string, *tg.InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("🔔 <b>Настройки уведомлений</b>\n\n")
	fmt.Fprintf(&b, "Интервалы: здоровье — %s, дрейф — %s, подписки — %s (меняются в telegram.yaml).\n\nКатегории:\n",
		ruDuration(notifications.HealthInterval), ruDuration(notifications.DriftInterval), ruDuration(notifications.SubscriptionRefresh))
	var rows [][]tg.InlineKeyboardButton
	for _, category := range notificationCategories {
		mark := "🔕"
		if enabled[category.Key] {
			mark = "🔔"
		}
		rows = append(rows, []tg.InlineKeyboardButton{btn(mark+" "+category.Title, "set:t:"+category.Key)})
	}
	b.WriteString("Нажатие переключает категорию; выбор сохраняется на хабе и переживает рестарт бота.")
	rows = append(rows, backRow)
	return b.String(), keyboard(rows...)
}
