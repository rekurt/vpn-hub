package bot

import (
	"context"
	"fmt"
	"sort"
	"strings"

	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

func (b *Bot) tunnelEntries(ctx context.Context) ([]tunnelEntry, error) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]tunnelEntry, 0, len(cfg.Tunnels))
	for _, tunnel := range cfg.Tunnels {
		entries = append(entries, tunnelEntry{Tunnel: tunnel, Health: b.health.get(tunnel.ID)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Tunnel.ID < entries[j].Tunnel.ID })
	return entries, nil
}

func (b *Bot) buildTunnels(ctx context.Context) screen {
	entries, err := b.tunnelEntries(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	return scr(renderTunnels(task2EnglishLocalizer, entries))
}

func (b *Bot) buildTunnelCard(ctx context.Context, tunnelID string) screen {
	entries, err := b.tunnelEntries(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	for _, entry := range entries {
		if entry.Tunnel.ID == tunnelID {
			return scr(renderTunnelCard(task2EnglishLocalizer, entry, b.Now()))
		}
	}
	return renderFailure("туннель не найден", fmt.Errorf("нет туннеля %q", tunnelID))
}

func (b *Bot) routeTunnels(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	if action != "" && action != "x" && action != "ta" && len(args) < 1 {
		return result{toast: "Не указан туннель"}
	}
	switch action {
	case "":
		return b.show(ctx, cb, b.buildTunnels(ctx))
	case "x":
		b.dialogs.clear()
		return b.show(ctx, cb, b.buildTunnels(ctx))
	case "c":
		return b.show(ctx, cb, b.buildTunnelCard(ctx, args[0]))
	case "on", "off":
		verb := map[string]string{"on": "Включить", "off": "Выключить"}[action]
		return b.show(ctx, cb, scr(renderConfirm(task2EnglishLocalizer,
			fmt.Sprintf("%s туннель <b>%s</b>?", verb, esc(args[0])),
			"tun:"+action+"!:"+args[0], "tun:c:"+args[0])))
	case "on!":
		return b.toggleTunnel(ctx, cb, args[0], true)
	case "off!":
		return b.toggleTunnel(ctx, cb, args[0], false)
	case "t":
		return b.testTunnel(ctx, cb, args[0])
	case "ra":
		b.dialogs.start(dialogRouteAdd, map[string]string{"tunnel": args[0]})
		return b.show(ctx, cb, screen{
			text:   fmt.Sprintf("➕ Какой маршрут добавить в <b>%s</b>? Пришлите подсеть, например <code>10.20.0.0/16</code>.", esc(args[0])),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "tun:x")}),
		})
	case "za":
		b.dialogs.start(dialogZoneAdd, map[string]string{"tunnel": args[0]})
		return b.show(ctx, cb, screen{
			text:   fmt.Sprintf("➕ Какую DNS-зону добавить в <b>%s</b>? Пришлите домен, например <code>corp.internal</code>.", esc(args[0])),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "tun:x")}),
		})
	case "rd":
		if len(args) < 2 {
			return result{toast: "Нет значения"}
		}
		return b.editTunnelList(ctx, cb, args[0], "routes", args[1], false)
	case "zd":
		if len(args) < 2 {
			return result{toast: "Нет значения"}
		}
		return b.editTunnelList(ctx, cb, args[0], "dns_zones", args[1], false)
	case "ta":
		return b.testAllTunnels(ctx, cb)
	case "ac":
		return b.show(ctx, cb, b.buildAccess(ctx, args[0]))
	case "at":
		if len(args) < 2 {
			return result{toast: "Нет устройства"}
		}
		return b.toggleAccess(ctx, cb, args[0], args[1])
	case "pr":
		b.dialogs.clear()
		return b.show(ctx, cb, b.buildProbes(ctx, args[0]))
	case "ps":
		if len(args) < 2 {
			return result{toast: "Нет вида пробы"}
		}
		return b.startProbeDialog(ctx, cb, args[0], args[1])
	case "pd":
		if len(args) < 2 {
			return result{toast: "Нет вида пробы"}
		}
		return b.removeProbe(ctx, cb, args[0], args[1])
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// toggleTunnel mirrors `hubctl tunnel enable/disable`, including the validate-then-
// revert discipline: disabling a tunnel a device depends on is refused with the
// exact reason.
func (b *Bot) toggleTunnel(ctx context.Context, cb *tg.CallbackQuery, tunnelID string, enable bool) result {
	name := "выключение туннеля "
	if enable {
		name = "включение туннеля "
	}
	release, busy := b.claim(name + tunnelID)
	if busy != nil {
		return *busy
	}
	defer release()

	if err := b.Editor.SetTunnelField(tunnelID, "enabled", fmt.Sprint(enable)); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit("Отменено, конфигурация не проходит проверку", err, func() error {
			return b.Editor.SetTunnelField(tunnelID, "enabled", fmt.Sprint(!enable))
		})
		view.markup = keyboard([]tg.InlineKeyboardButton{btn("⬅️ К туннелю", "tun:c:"+tunnelID)})
		return b.show(ctx, cb, view)
	}
	state := "выключен"
	if enable {
		state = "включён"
	}
	outcome := b.show(ctx, cb, b.afterConfigChange(fmt.Sprintf("Туннель <b>%s</b> %s.", esc(tunnelID), state), backToTunnels))
	outcome.toast = "Готово"
	return outcome
}

// editTunnelList adds or removes a routes/dns_zones entry. As in the CLI, a change
// that was written but no longer validates is reported rather than silently left to
// fail at deploy.
func (b *Bot) editTunnelList(ctx context.Context, cb *tg.CallbackQuery, tunnelID, field, value string, add bool) result {
	release, busy := b.claim("правка " + field + " у " + tunnelID)
	if busy != nil {
		return *busy
	}
	defer release()

	var err error
	if add {
		err = b.Editor.AppendListItem(tunnelID, field, value)
	} else {
		err = b.Editor.RemoveListItem(tunnelID, field, value)
	}
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		// Revert, like every other mutator does. AppendListItem/RemoveListItem write
		// the value without semantic checks, so a mistyped route or zone leaves the
		// config unloadable -- and because every bot screen calls LoadAndValidate,
		// the whole UI (including the button that would remove the bad value) breaks,
		// forcing an SSH fix. Undo the write so the config stays deployable.
		var revertErr error
		if add {
			revertErr = b.Editor.RemoveListItem(tunnelID, field, value)
		} else {
			revertErr = b.Editor.AppendListItem(tunnelID, field, value)
		}
		if revertErr != nil {
			return b.show(ctx, cb, screen{
				text: "⚠️ Изменение сделало конфигурацию невалидной, и откат не удался:\n<code>" +
					esc(revertErr.Error()) + "</code>\n\nПравьте конфигурацию на хосте.",
				markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ К туннелю", "tun:c:"+tunnelID)}),
			})
		}
		return b.show(ctx, cb, screen{
			text: "↩️ Изменение отменено, конфигурация не проходит проверку:\n<code>" +
				esc(err.Error()) + "</code>",
			markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ К туннелю", "tun:c:"+tunnelID)}),
		})
	}
	outcome := b.show(ctx, cb, b.buildTunnelCard(ctx, tunnelID))
	// Name what changed -- a one-tap removal otherwise leaves no trace of which
	// value went. Routes and zones, unlike a subscription upstream, only take
	// effect on a deploy, so say that too.
	verb := "добавлено"
	if !add {
		verb = "удалено"
	}
	outcome.toast = clampToast(fmt.Sprintf("%s: %s — вступит в силу после деплоя", verb, value))
	return outcome
}

// testTunnel probes in the background: probes take seconds, and the update loop
// must not stand still while curl waits inside a namespace.
func (b *Bot) testTunnel(ctx context.Context, cb *tg.CallbackQuery, tunnelID string) result {
	b.spawn("test-"+tunnelID, func() {
		cfg, err := b.Service.LoadAndValidate(ctx)
		if err != nil {
			b.sendScreen(ctx, renderFailure("конфигурация не читается", err))
			return
		}
		health, err := b.Service.TestTunnel(ctx, cfg, tunnelID)
		if err != nil {
			b.sendScreen(ctx, renderFailure("проба не запустилась", err))
			return
		}
		b.health.store(healthEntry{ID: tunnelID, Status: health.Status, Reason: health.Reason, CheckedAt: health.CheckedAt})
		b.show(ctx, cb, b.buildTunnelCard(ctx, tunnelID))
	})
	return result{toast: "🩺 Проверяю…"}
}

// testAllTunnels probes every enabled tunnel in the background, editing one
// progress message; the health board keeps the results for the other screens.
func (b *Bot) testAllTunnels(ctx context.Context, _ *tg.CallbackQuery) result {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.sendScreen(ctx, renderFailure("конфигурация не читается", err))
		return result{}
	}
	var subjects []domain.Tunnel
	for _, tunnel := range cfg.Tunnels {
		if tunnel.IsEnabled() {
			subjects = append(subjects, tunnel)
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].ID < subjects[j].ID })
	if len(subjects) == 0 {
		return result{toast: "Нет включённых туннелей"}
	}

	message, err := b.API.SendMessage(ctx, b.Cfg.AdminID,
		fmt.Sprintf("🩺 Проверяю %d %s…", len(subjects), plural(task2EnglishLocalizer, len(subjects), msgPluralTunnelOne, msgPluralTunnelFew, msgPluralTunnelMany)), nil)
	if err != nil {
		return result{toast: "Не удалось начать: " + err.Error(), alert: true}
	}

	b.spawn("test-all", func() {
		var lines []string
		for index, tunnel := range subjects {
			text := fmt.Sprintf("🩺 %d из %d: проверяю <code>%s</code>…\n%s",
				index+1, len(subjects), esc(tunnel.ID), strings.Join(lines, "\n"))
			if err := b.API.EditMessageText(ctx, message.Chat.ID, message.ID, text, nil); err != nil {
				b.logf("test-all edit: %v", err)
			}

			health, err := b.Service.TestTunnel(ctx, cfg, tunnel.ID)
			if err != nil {
				lines = append(lines, fmt.Sprintf("⚪️ <code>%s</code> — проба не запустилась: %s", esc(tunnel.ID), esc(err.Error())))
				continue
			}
			b.health.store(healthEntry{ID: tunnel.ID, Status: health.Status, Reason: health.Reason, CheckedAt: health.CheckedAt})
			lines = append(lines, fmt.Sprintf("%s <code>%s</code> — %s", healthIcon(health.Status), esc(tunnel.ID), esc(health.Reason)))
		}
		final := "🩺 <b>Проверка завершена</b>\n\n" + strings.Join(lines, "\n")
		view := screen{text: final, markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚇 Туннели", "tun"), btn("📊 Статус", "st")},
		)}
		if err := b.API.EditMessageText(ctx, message.Chat.ID, message.ID, view.text, view.markup); err != nil {
			b.logf("test-all edit: %v", err)
		}
	})
	return result{toast: "Проверяю все"}
}

// --- allowed_devices -------------------------------------------------------

func (b *Bot) buildAccess(ctx context.Context, tunnelID string) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	devices := make([]string, 0, len(cfg.Devices))
	for _, device := range cfg.Devices {
		devices = append(devices, device.ID)
	}
	sort.Strings(devices)
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == tunnelID {
			return scr(renderAccess(task2EnglishLocalizer, tunnelID, devices, tunnel.AllowedDevices))
		}
	}
	return renderFailure("туннель не найден", fmt.Errorf("нет туннеля %q", tunnelID))
}

// toggleAccess flips one device in allowed_devices, with the usual revert when the
// resulting config no longer validates -- excluding the only device that uses this
// egress is exactly the mistake validation exists to catch.
func (b *Bot) toggleAccess(ctx context.Context, cb *tg.CallbackQuery, tunnelID, deviceID string) result {
	release, busy := b.claim("доступ к " + tunnelID)
	if busy != nil {
		return *busy
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("конфигурация не читается", err))
	}
	allowed := false
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == tunnelID {
			for _, id := range tunnel.AllowedDevices {
				if id == deviceID {
					allowed = true
				}
			}
		}
	}

	if allowed {
		err = b.Editor.RemoveListItem(tunnelID, "allowed_devices", deviceID)
	} else {
		err = b.Editor.AppendListItem(tunnelID, "allowed_devices", deviceID)
	}
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit("Отменено, конфигурация не проходит проверку", err, func() error {
			if allowed {
				return b.Editor.AppendListItem(tunnelID, "allowed_devices", deviceID)
			}
			return b.Editor.RemoveListItem(tunnelID, "allowed_devices", deviceID)
		})
		return b.show(ctx, cb, screen{
			text:   view.text,
			markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ К доступу", "tun:ac:"+tunnelID)}),
		})
	}
	outcome := b.show(ctx, cb, b.buildAccess(ctx, tunnelID))
	outcome.toast = "Изменение вступит в силу после деплоя"
	return outcome
}

// handleListAddInput consumes the route/zone dialog answer.
func (b *Bot) handleListAddInput(ctx context.Context, dialog *dialog, text string) {
	tunnelID := dialog.data["tunnel"]
	field := "routes"
	if dialog.kind == dialogZoneAdd {
		field = "dns_zones"
	}
	b.dialogs.clear()
	outcome := b.editTunnelList(ctx, nil, tunnelID, field, text, true)
	if outcome.toast != "" && outcome.toast != "Готово" {
		b.send(ctx, "⚠️ "+esc(outcome.toast), keyboard([]tg.InlineKeyboardButton{btn("⬅️ К туннелю", "tun:c:"+tunnelID)}))
	}
}
