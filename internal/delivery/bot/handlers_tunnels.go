package bot

import (
	"context"
	"fmt"
	"sort"

	tg "vpn-hub/internal/adapters/telegram"
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
	return scr(renderTunnels(entries))
}

func (b *Bot) buildTunnelCard(ctx context.Context, tunnelID string) screen {
	entries, err := b.tunnelEntries(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	for _, entry := range entries {
		if entry.Tunnel.ID == tunnelID {
			return scr(renderTunnelCard(entry, b.Now()))
		}
	}
	return renderFailure("туннель не найден", fmt.Errorf("нет туннеля %q", tunnelID))
}

func (b *Bot) routeTunnels(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	if action != "" && action != "x" && len(args) < 1 {
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
		return b.show(ctx, cb, scr(renderConfirm(
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
	release, busyWith, ok := b.gate.Acquire(name + tunnelID)
	if !ok {
		return result{toast: "⏳ Занято: " + busyWith, alert: true}
	}
	defer release()

	if err := b.Editor.SetTunnelField(tunnelID, "enabled", fmt.Sprint(enable)); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.SetTunnelField(tunnelID, "enabled", fmt.Sprint(!enable))
		return b.show(ctx, cb, screen{
			text:   "↩️ Отменено, конфигурация не проходит проверку:\n<code>" + esc(err.Error()) + "</code>",
			markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ К туннелю", "tun:c:"+tunnelID)}),
		})
	}
	state := "выключен"
	if enable {
		state = "включён"
	}
	outcome := b.show(ctx, cb, b.afterConfigChange(ctx,
		fmt.Sprintf("Туннель <b>%s</b> %s.", esc(tunnelID), state)))
	outcome.toast = "Готово"
	return outcome
}

// editTunnelList adds or removes a routes/dns_zones entry. As in the CLI, a change
// that was written but no longer validates is reported rather than silently left to
// fail at deploy.
func (b *Bot) editTunnelList(ctx context.Context, cb *tg.CallbackQuery, tunnelID, field, value string, add bool) result {
	release, busyWith, ok := b.gate.Acquire("правка " + field + " у " + tunnelID)
	if !ok {
		return result{toast: "⏳ Занято: " + busyWith, alert: true}
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
		return b.show(ctx, cb, screen{
			text: "⚠️ Изменение записано, но конфигурация теперь не проходит проверку и не задеплоится:\n<code>" +
				esc(err.Error()) + "</code>",
			markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ К туннелю", "tun:c:"+tunnelID)}),
		})
	}
	outcome := b.show(ctx, cb, b.buildTunnelCard(ctx, tunnelID))
	outcome.toast = "Готово"
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
