package bot

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	configadapter "vpn-hub/internal/adapters/config"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

func (b *Bot) clientACLEntries(ctx context.Context) ([]clientACLEntry, []string, error) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return nil, nil, err
	}
	devices := make([]string, 0, len(cfg.Devices))
	for _, device := range cfg.Devices {
		devices = append(devices, device.ID)
	}
	sort.Strings(devices)
	entries := make([]clientACLEntry, 0, len(cfg.ClientACLs))
	for index, rule := range cfg.ClientACLs {
		entries = append(entries, clientACLEntry{Rule: rule, Ordinal: index})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i].Rule, entries[j].Rule
		switch {
		case left.Source != right.Source:
			return left.Source < right.Source
		case left.Target != right.Target:
			return left.Target < right.Target
		case left.Protocol != right.Protocol:
			return left.Protocol < right.Protocol
		default:
			return left.Port < right.Port
		}
	})
	return entries, devices, nil
}

func (b *Bot) buildClientACLs(ctx context.Context) screen {
	entries, _, err := b.clientACLEntries(ctx)
	if err != nil {
		return renderFailure(b.L, "конфигурация не читается", err)
	}
	return scr(renderClientACLs(b.L, entries))
}

func (b *Bot) routeClientACLs(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildClientACLs(ctx))
	case "x":
		b.dialogs.clear()
		return b.show(ctx, cb, b.buildClientACLs(ctx))
	case "add":
		_, devices, err := b.clientACLEntries(ctx)
		if err != nil {
			return b.show(ctx, cb, renderFailure(b.L, "конфигурация не читается", err))
		}
		return b.show(ctx, cb, scr(renderClientACLSource(b.L, devices)))
	case "src":
		if len(args) < 1 {
			return result{toast: "Нет source"}
		}
		_, devices, err := b.clientACLEntries(ctx)
		if err != nil {
			return b.show(ctx, cb, renderFailure(b.L, "конфигурация не читается", err))
		}
		return b.show(ctx, cb, scr(renderClientACLTarget(b.L, args[0], devices)))
	case "tgt":
		if len(args) < 2 {
			return result{toast: "Нет target"}
		}
		b.dialogs.start(dialogClientACL, map[string]string{"source": args[0], "target": args[1]})
		return b.show(ctx, cb, screen{
			text:   fmt.Sprintf("Шаг 3 из 3. Какой порт открыть для <code>%s</code> → <code>%s</code>?\n\nПришлите <code>tcp/22</code> или <code>udp/53</code>.", esc(args[0]), esc(args[1])),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "acl:x")}),
		})
	case "rm":
		if len(args) < 1 {
			return result{toast: "Нет правила"}
		}
		entries, _, err := b.clientACLEntries(ctx)
		if err != nil {
			return b.show(ctx, cb, renderFailure(b.L, "конфигурация не читается", err))
		}
		var target *domain.ClientACL
		for _, entry := range entries {
			if fmt.Sprint(entry.Ordinal) == args[0] {
				rule := entry.Rule
				target = &rule
			}
		}
		if target == nil {
			return result{toast: "Правило уже изменилось", alert: true}
		}
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			fmt.Sprintf("Удалить доступ <code>%s</code> → <code>%s</code> <code>%s/%d</code>?", esc(target.Source), esc(target.Target), esc(string(target.Protocol)), target.Port),
			"acl:rm!:"+args[0], "acl")))
	case "rm!":
		if len(args) < 1 {
			return result{toast: "Нет правила"}
		}
		return b.removeClientACL(ctx, cb, args[0])
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

func (b *Bot) handleClientACLInput(ctx context.Context, dialog *dialog, text string) {
	protocol, port, err := parseClientACLSpec(text)
	if err != nil {
		b.send(ctx, "⚠️ "+err.Error()+"\n\nПришлите, например, <code>tcp/22</code>.", keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "acl:x")}))
		return
	}
	b.dialogs.clear()
	b.addClientACL(ctx, nil, dialog.data["source"], dialog.data["target"], protocol, port)
}

func (b *Bot) addClientACL(ctx context.Context, cb *tg.CallbackQuery, source, target string, protocol domain.ClientACLProtocol, port uint16) result {
	release, busy := b.claim(newOperation(msgOperationClientACLEdit))
	if busy != nil {
		return *busy
	}
	defer release()
	editor := configadapter.Editor{Root: b.ConfigPath}
	if err := editor.AddClientACL(source, target, string(protocol), port); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit(b.L, "Изменение отменено, конфигурация не проходит проверку", err, func() error {
			return editor.RemoveClientACL(source, target, string(protocol), port)
		})
		return b.show(ctx, cb, view)
	}
	text := fmt.Sprintf("🔐 Разрешён доступ <b>%s</b> → <b>%s</b> <code>%s/%d</code>.", esc(source), esc(target), esc(string(protocol)), port)
	return b.show(ctx, cb, legacyRussianACLAfterConfigChange(text))
}

func (b *Bot) removeClientACL(ctx context.Context, cb *tg.CallbackQuery, ordinal string) result {
	entries, _, err := b.clientACLEntries(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, "конфигурация не читается", err))
	}
	var target *domain.ClientACL
	for _, entry := range entries {
		if fmt.Sprint(entry.Ordinal) == ordinal {
			rule := entry.Rule
			target = &rule
		}
	}
	if target == nil {
		return result{toast: "Правило уже изменилось", alert: true}
	}
	release, busy := b.claim(newOperation(msgOperationClientACLEdit))
	if busy != nil {
		return *busy
	}
	defer release()
	editor := configadapter.Editor{Root: b.ConfigPath}
	if err := editor.RemoveClientACL(target.Source, target.Target, string(target.Protocol), target.Port); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit(b.L, "Изменение отменено, конфигурация не проходит проверку", err, func() error {
			return editor.AddClientACL(target.Source, target.Target, string(target.Protocol), target.Port)
		})
		return b.show(ctx, cb, view)
	}
	return b.show(ctx, cb, legacyRussianACLAfterConfigChange("🔐 Правило удалено."))
}

func legacyRussianACLAfterConfigChange(text string) screen {
	return screen{
		text: text + "\n\nИзменение вступит в силу после деплоя.",
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚀 Деплой", "dep")},
			backToACLs,
		),
	}
}

func parseClientACLSpec(value string) (domain.ClientACLProtocol, uint16, error) {
	protocol, rawPort, ok := strings.Cut(strings.ToLower(strings.TrimSpace(value)), "/")
	if !ok || rawPort == "" {
		return "", 0, fmt.Errorf("порт должен выглядеть как tcp/22 или udp/53")
	}
	if protocol != string(domain.ClientACLTCP) && protocol != string(domain.ClientACLUDP) {
		return "", 0, fmt.Errorf("протокол должен быть tcp или udp")
	}
	port64, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port64 == 0 {
		return "", 0, fmt.Errorf("порт должен быть от 1 до 65535")
	}
	return domain.ClientACLProtocol(protocol), uint16(port64), nil
}

var backToACLs = []tg.InlineKeyboardButton{btn("🔐 ACL", "acl"), btn("🏠 Меню", "m")}
