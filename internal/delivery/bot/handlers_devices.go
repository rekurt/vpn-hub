package bot

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"

	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

func (b *Bot) deviceEntries(ctx context.Context) ([]deviceEntry, error) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return nil, err
	}
	revoked, err := b.Revocations.Load(ctx)
	if err != nil {
		return nil, err
	}
	revokedSet := map[string]bool{}
	for _, id := range revoked {
		revokedSet[id] = true
	}

	// The live interface tells who is actually connected. Failing to observe it
	// (workstation, stopped hub) degrades presence to unknown, not the screen.
	peers := map[string]domain.PeerObservation{}
	if observed, err := b.Peers.Observe(ctx, application.IngressInterface); err == nil {
		for _, peer := range observed.Peers {
			peers[peer.PublicKey] = peer
		}
	}

	now := b.Now()
	entries := make([]deviceEntry, 0, len(cfg.Devices))
	for _, device := range cfg.Devices {
		entry := deviceEntry{
			ID: device.ID, Address: device.Address, PublicKey: device.PublicKey,
			Egress: device.Egress, Revoked: revokedSet[device.ID], Now: now,
		}
		if peer, exists := peers[device.PublicKey]; exists {
			entry.Peer = &peer
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

func (b *Bot) buildDevices(ctx context.Context) screen {
	entries, err := b.deviceEntries(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	return scr(renderDevices(entries))
}

func (b *Bot) buildDeviceCard(ctx context.Context, deviceID string) screen {
	entries, err := b.deviceEntries(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	for _, entry := range entries {
		if entry.ID == deviceID {
			return scr(renderDeviceCard(entry))
		}
	}
	return renderFailure("устройство не найдено", fmt.Errorf("нет устройства %q", deviceID))
}

// egressChoices lists what a device may leave through: enabled egress tunnels and
// the direct path.
func (b *Bot) egressChoices(cfg domain.Config) []string {
	choices := []string{}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.Role == domain.RoleEgress && tunnel.IsEnabled() {
			choices = append(choices, tunnel.ID)
		}
	}
	sort.Strings(choices)
	return append(choices, domain.EgressDirect)
}

func (b *Bot) routeDevices(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildDevices(ctx))
	case "x":
		b.dialogs.clear()
		return b.show(ctx, cb, b.buildDevices(ctx))
	case "c":
		if len(args) < 1 {
			return result{toast: "Не указано устройство"}
		}
		return b.show(ctx, cb, b.buildDeviceCard(ctx, args[0]))
	case "eg":
		return b.routeDeviceEgress(ctx, cb, args)
	case "add":
		return b.routeDeviceAdd(ctx, cb, args)
	case "rv":
		if len(args) < 1 {
			return result{toast: "Не указано устройство"}
		}
		return b.show(ctx, cb, scr(renderConfirm(
			fmt.Sprintf("Отозвать <b>%s</b>? После деплоя устройство потеряет доступ.", esc(args[0])),
			"dev:rv!:"+args[0], "dev:c:"+args[0])))
	case "rv!":
		if len(args) < 1 {
			return result{toast: "Не указано устройство"}
		}
		return b.revokeDevice(ctx, cb, args[0])
	case "re":
		if len(args) < 1 {
			return result{toast: "Не указано устройство"}
		}
		return b.show(ctx, cb, scr(renderConfirm(
			fmt.Sprintf("Перевыпустить профиль <b>%s</b>? Будет новый ключ; старый профиль перестанет работать после деплоя.", esc(args[0])),
			"dev:re!:"+args[0], "dev:c:"+args[0])))
	case "re!":
		if len(args) < 1 {
			return result{toast: "Не указано устройство"}
		}
		return b.reissueDevice(ctx, cb, args[0])
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// --- set-egress ------------------------------------------------------------

func (b *Bot) routeDeviceEgress(ctx context.Context, cb *tg.CallbackQuery, args []string) result {
	if len(args) < 1 {
		return result{toast: "Не указано устройство"}
	}
	deviceID := args[0]
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("конфигурация не читается", err))
	}
	current := ""
	for _, device := range cfg.Devices {
		if device.ID == deviceID {
			current = device.Egress
		}
	}
	if current == "" {
		return result{toast: "Устройство не найдено", alert: true}
	}

	if len(args) == 1 {
		return b.show(ctx, cb, scr(renderEgressChoice(deviceID, current, b.egressChoices(cfg))))
	}

	target := args[1]
	if target == current {
		return result{toast: "Уже так"}
	}
	release, busyWith, ok := b.gate.Acquire("смена egress " + deviceID)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	// The same write-validate-revert dance as `hubctl device set-egress`: the
	// operator hears about a config that stopped validating now, not at deploy.
	if err := b.Editor.SetDeviceField(deviceID, "egress", target); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.SetDeviceField(deviceID, "egress", current)
		return b.show(ctx, cb, screen{
			text:   fmt.Sprintf("↩️ Изменение отменено, конфигурация не проходит проверку:\n<code>%s</code>", esc(err.Error())),
			markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ К устройству", "dev:c:"+deviceID)}),
		})
	}
	outcome := b.show(ctx, cb, b.afterConfigChange(fmt.Sprintf("🔀 <b>%s</b> теперь выходит через <b>%s</b>.", esc(deviceID), esc(target)), backToDevices))
	outcome.toast = "Готово"
	return outcome
}

// afterConfigChange reminds that edits do nothing until deployed -- the same
// sentence hubctl prints, as buttons. The back row names the section the change was
// made in, so the operator returns where they were rather than always to devices.
func (b *Bot) afterConfigChange(text string, back []tg.InlineKeyboardButton) screen {
	return screen{
		text: text + "\n\nИзменение вступит в силу после деплоя.",
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚀 Деплой", "dep")},
			back,
		),
	}
}

// backToDevices and backToTunnels are the two return rows config edits use.
var backToDevices = []tg.InlineKeyboardButton{btn("📱 Устройства", "dev"), btn("🏠 Меню", "m")}
var backToTunnels = []tg.InlineKeyboardButton{btn("🚇 Туннели", "tun"), btn("🏠 Меню", "m")}

// --- add -------------------------------------------------------------------

var deviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

func (b *Bot) routeDeviceAdd(ctx context.Context, cb *tg.CallbackQuery, args []string) result {
	if len(args) == 0 {
		b.dialogs.start(dialogDeviceAdd, nil)
		return b.show(ctx, cb, screen{
			text:   "➕ <b>Новое устройство</b>\n\nШаг 1 из 3. Введите id: латиница в нижнем регистре, цифры, дефис (например <code>phone-anna</code>).",
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "dev:x")}),
		})
	}

	dialog := b.dialogs.current()
	if dialog == nil || dialog.kind != dialogDeviceAdd {
		return result{toast: "Диалог уже завершён", alert: true}
	}
	switch args[0] {
	case "addr":
		if len(args) < 2 {
			return result{toast: "Нет адреса"}
		}
		dialog.data["address"] = args[1]
		dialog.step = 2
		return b.show(ctx, cb, b.deviceAddEgressStep(ctx))
	case "eg":
		if len(args) < 2 {
			return result{toast: "Нет egress"}
		}
		return b.finishDeviceAdd(ctx, cb, args[1])
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

func (b *Bot) deviceAddEgressStep(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.dialogs.clear()
		return renderFailure("конфигурация не читается", err)
	}
	var rows [][]tg.InlineKeyboardButton
	for _, egress := range b.egressChoices(cfg) {
		rows = append(rows, []tg.InlineKeyboardButton{btn(egress, "dev:add:eg:"+egress)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("✖️ Отмена", "dev:x")})
	return screen{
		text:   "Шаг 3 из 3. Через что выпускать устройство в интернет?",
		markup: keyboard(rows...),
	}
}

// handleDeviceAddInput consumes the dialog's text answers: the id, then the address.
func (b *Bot) handleDeviceAddInput(ctx context.Context, dialog *dialog, text string) {
	switch dialog.step {
	case 0:
		if !deviceIDPattern.MatchString(text) {
			b.send(ctx, "⚠️ Такой id не подойдёт: латиница в нижнем регистре, цифры, дефис. Попробуйте ещё раз или /cancel.", nil)
			return
		}
		dialog.data["id"] = text
		dialog.step = 1

		prompt := fmt.Sprintf("Шаг 2 из 3. Адрес устройства внутри клиентской сети (host-маршрут, например <code>%s</code>).", esc("10.80.0.2/32"))
		var markup *tg.InlineKeyboardMarkup
		if cfg, err := b.Service.LoadAndValidate(ctx); err == nil {
			if suggestion := nextFreeAddress(cfg); suggestion != "" {
				prompt = fmt.Sprintf("Шаг 2 из 3. Адрес устройства. Свободен <code>%s</code> — можно взять его или прислать свой.", esc(suggestion))
				markup = keyboard(
					[]tg.InlineKeyboardButton{btn("Использовать "+suggestion, "dev:add:addr:"+suggestion)},
					[]tg.InlineKeyboardButton{btn("✖️ Отмена", "dev:x")},
				)
			}
		}
		b.send(ctx, prompt, markup)
	case 1:
		if err := validateHostRoute(text); err != nil {
			b.send(ctx, "⚠️ "+esc(err.Error())+". Попробуйте ещё раз или /cancel.", nil)
			return
		}
		dialog.data["address"] = text
		dialog.step = 2
		b.sendScreen(ctx, b.deviceAddEgressStep(ctx))
	default:
		b.send(ctx, "Выберите egress кнопкой выше, или /cancel.", nil)
	}
}

func validateHostRoute(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("адрес должен быть host-маршрутом вида 10.80.0.2/32")
	}
	bits := 32
	if prefix.Addr().Is6() {
		bits = 128
	}
	if prefix.Bits() != bits {
		return fmt.Errorf("адрес должен быть host-маршрутом, то есть /%d", bits)
	}
	return nil
}

// nextFreeAddress proposes the first unused host address in the client network.
func nextFreeAddress(cfg domain.Config) string {
	prefix, err := netip.ParsePrefix(cfg.Hub.ClientCIDR)
	if err != nil {
		return ""
	}
	used := map[string]bool{}
	for _, device := range cfg.Devices {
		if devicePrefix, err := netip.ParsePrefix(device.Address); err == nil {
			used[devicePrefix.Addr().String()] = true
		}
	}
	if hub, err := netip.ParseAddr(cfg.Hub.DNSAddress); err == nil {
		used[hub.String()] = true
	}

	address := prefix.Masked().Addr()
	for range 65536 {
		address = address.Next()
		if !prefix.Contains(address) {
			return ""
		}
		if used[address.String()] {
			continue
		}
		if address.Is6() {
			return address.String() + "/128"
		}
		return address.String() + "/32"
	}
	return ""
}

func (b *Bot) finishDeviceAdd(ctx context.Context, cb *tg.CallbackQuery, egress string) result {
	dialog := b.dialogs.current()
	if dialog == nil || dialog.kind != dialogDeviceAdd || dialog.data["id"] == "" || dialog.data["address"] == "" {
		return result{toast: "Диалог уже завершён", alert: true}
	}
	deviceID, address := dialog.data["id"], dialog.data["address"]

	release, busyWith, ok := b.gate.Acquire("добавление устройства " + deviceID)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("конфигурация не читается", err))
	}

	// The private key exists only inside this call: it goes into the profile that
	// leaves through the chat, and the hub keeps the public half in the config.
	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return b.show(ctx, cb, renderFailure("не удалось сгенерировать ключ", err))
	}
	if err := b.Editor.AddDevice(deviceID, address, publicKey, egress); err != nil {
		return b.show(ctx, cb, renderFailure("устройство не добавилось", err))
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.RemoveDevice(deviceID)
		return b.show(ctx, cb, renderFailure("отменено: конфигурация с новым устройством не проходит проверку", err))
	}
	b.dialogs.clear()

	if outcome := b.sendProfile(ctx, cfg.Hub, deviceID, address, privateKey); outcome != nil {
		return *outcome
	}
	view := b.afterConfigChange(fmt.Sprintf("✅ Устройство <b>%s</b> добавлено (%s → %s).\nПрофиль и QR-код выше — доставьте их на устройство и удалите из чата.", esc(deviceID), esc(address), esc(egress)), backToDevices)
	b.sendScreen(ctx, view)
	return result{toast: "Устройство добавлено"}
}

// sendProfile renders the client profile and delivers it as a file plus a QR code.
// A non-nil result is the failure to report.
func (b *Bot) sendProfile(ctx context.Context, hub domain.Hub, deviceID, address, privateKey string) *result {
	profile, err := b.Profiles.Render(hub, address, privateKey)
	if err != nil {
		b.sendScreen(ctx, renderFailure("профиль не отрендерился", err))
		return &result{toast: "Ошибка"}
	}
	if _, err := b.API.SendDocument(ctx, b.Cfg.AdminID, deviceID+".conf", []byte(profile),
		"Профиль AmneziaWG для <b>"+esc(deviceID)+"</b>"); err != nil {
		b.sendScreen(ctx, renderFailure("не удалось отправить профиль", err))
		return &result{toast: "Ошибка"}
	}
	// The QR code is a convenience; the profile file above already succeeded, so a
	// missing qrencode degrades politely rather than failing the whole flow.
	if image, err := b.QR.PNG(ctx, profile); err != nil {
		b.send(ctx, "⚠️ QR-код не получился: <code>"+esc(err.Error())+"</code>", nil)
	} else if _, err := b.API.SendPhoto(ctx, b.Cfg.AdminID, deviceID+".png", image,
		"Сканировать в приложении AmneziaWG"); err != nil {
		b.logf("sendPhoto: %v", err)
	}
	return nil
}

// --- reissue / revoke ------------------------------------------------------

func (b *Bot) reissueDevice(ctx context.Context, cb *tg.CallbackQuery, deviceID string) result {
	release, busyWith, ok := b.gate.Acquire("перевыпуск профиля " + deviceID)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("конфигурация не читается", err))
	}
	var device domain.Device
	for _, candidate := range cfg.Devices {
		if candidate.ID == deviceID {
			device = candidate
		}
	}
	if device.ID == "" {
		return result{toast: "Устройство не найдено", alert: true}
	}

	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return b.show(ctx, cb, renderFailure("не удалось сгенерировать ключ", err))
	}
	if err := b.Editor.SetDeviceField(deviceID, "public_key", publicKey); err != nil {
		return b.show(ctx, cb, renderFailure("ключ не записался", err))
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.SetDeviceField(deviceID, "public_key", device.PublicKey)
		return b.show(ctx, cb, renderFailure("отменено: конфигурация не проходит проверку", err))
	}
	// A re-issued device is meant to work again: lifting the revocation is part of
	// the same operation, not a separate thing to remember.
	b.self.mark(b.Now())
	if err := b.Revocations.Remove(ctx, deviceID); err != nil {
		b.send(ctx, "⚠️ Отзыв не снялся: <code>"+esc(err.Error())+"</code>", nil)
	}

	if outcome := b.sendProfile(ctx, cfg.Hub, deviceID, device.Address, privateKey); outcome != nil {
		return *outcome
	}
	view := b.afterConfigChange(fmt.Sprintf("📤 Профиль <b>%s</b> перевыпущен, отзыв снят (если был).\nСтарый профиль перестанет работать после деплоя.", esc(deviceID)), backToDevices)
	b.sendScreen(ctx, view)
	return result{toast: "Профиль перевыпущен"}
}

func (b *Bot) revokeDevice(ctx context.Context, cb *tg.CallbackQuery, deviceID string) result {
	release, busyWith, ok := b.gate.Acquire("отзыв устройства " + deviceID)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	b.self.mark(b.Now())
	if err := b.Revocations.Add(ctx, deviceID); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	outcome := b.show(ctx, cb, b.afterConfigChange(fmt.Sprintf("🚫 Устройство <b>%s</b> отозвано.", esc(deviceID)), backToDevices))
	outcome.toast = "Отозвано"
	return outcome
}
