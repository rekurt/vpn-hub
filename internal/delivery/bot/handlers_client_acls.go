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

const (
	msgACLSourceRequired    MessageID = "acl/source_required"
	msgACLTargetRequired    MessageID = "acl/target_required"
	msgACLRuleRequired      MessageID = "acl/rule_required"
	msgACLPortStep          MessageID = "acl/port_step"
	msgACLRuleStale         MessageID = "acl/rule_stale"
	msgACLRemoveConfirm     MessageID = "acl/remove_confirm"
	msgACLSpecRetry         MessageID = "acl/spec_retry"
	msgACLSpecFormatError   MessageID = "acl/spec_format_error"
	msgACLSpecProtocolError MessageID = "acl/spec_protocol_error"
	msgACLSpecPortError     MessageID = "acl/spec_port_error"
	msgFailureACLEdit       MessageID = "failure/acl_edit"
	msgACLAllowed           MessageID = "acl/allowed"
	msgACLRemoved           MessageID = "acl/removed"
	msgACLAfterChange       MessageID = "acl/after_change"
	msgRevertACLInvalid     MessageID = "revert/acl_invalid"
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
		return renderFailure(b.L, b.text(msgFailureConfigUnreadable), err)
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
			return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
		}
		return b.show(ctx, cb, scr(renderClientACLSource(b.L, devices)))
	case "src":
		if len(args) < 1 {
			return result{toast: b.text(msgACLSourceRequired)}
		}
		_, devices, err := b.clientACLEntries(ctx)
		if err != nil {
			return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
		}
		return b.show(ctx, cb, scr(renderClientACLTarget(b.L, args[0], devices)))
	case "tgt":
		if len(args) < 2 {
			return result{toast: b.text(msgACLTargetRequired)}
		}
		b.dialogs.start(dialogClientACL, map[string]string{"source": args[0], "target": args[1]})
		return b.show(ctx, cb, screen{
			text:   b.text(msgACLPortStep, esc(args[0]), esc(args[1])),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "acl:x")}),
		})
	case "rm":
		if len(args) < 1 {
			return result{toast: b.text(msgACLRuleRequired)}
		}
		entries, _, err := b.clientACLEntries(ctx)
		if err != nil {
			return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
		}
		var target *domain.ClientACL
		for _, entry := range entries {
			if fmt.Sprint(entry.Ordinal) == args[0] {
				rule := entry.Rule
				target = &rule
			}
		}
		if target == nil {
			return result{toast: b.text(msgACLRuleStale), alert: true}
		}
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			b.text(msgACLRemoveConfirm, esc(target.Source), esc(target.Target), esc(string(target.Protocol)), target.Port),
			"acl:rm!:"+args[0], "acl")))
	case "rm!":
		if len(args) < 1 {
			return result{toast: b.text(msgACLRuleRequired)}
		}
		return b.removeClientACL(ctx, cb, args[0])
	default:
		return result{toast: b.text(msgUnknownButton)}
	}
}

func (b *Bot) handleClientACLInput(ctx context.Context, dialog *dialog, text string) {
	protocol, port, validation := parseClientACLSpec(text)
	if validation != "" {
		b.send(ctx, b.text(msgACLSpecRetry, b.text(validation)), keyboard([]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "acl:x")}))
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
		b.logf("add client ACL: %v", err)
		return result{toast: b.text(msgFailureACLEdit), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit(b.L, b.text(msgRevertACLInvalid), err, func() error {
			return editor.RemoveClientACL(source, target, string(protocol), port)
		})
		return b.show(ctx, cb, view)
	}
	text := b.text(msgACLAllowed, esc(source), esc(target), esc(string(protocol)), port)
	return b.show(ctx, cb, b.afterACLChange(text))
}

func (b *Bot) removeClientACL(ctx context.Context, cb *tg.CallbackQuery, ordinal string) result {
	entries, _, err := b.clientACLEntries(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
	}
	var target *domain.ClientACL
	for _, entry := range entries {
		if fmt.Sprint(entry.Ordinal) == ordinal {
			rule := entry.Rule
			target = &rule
		}
	}
	if target == nil {
		return result{toast: b.text(msgACLRuleStale), alert: true}
	}
	release, busy := b.claim(newOperation(msgOperationClientACLEdit))
	if busy != nil {
		return *busy
	}
	defer release()
	editor := configadapter.Editor{Root: b.ConfigPath}
	if err := editor.RemoveClientACL(target.Source, target.Target, string(target.Protocol), target.Port); err != nil {
		b.logf("remove client ACL: %v", err)
		return result{toast: b.text(msgFailureACLEdit), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit(b.L, b.text(msgRevertACLInvalid), err, func() error {
			return editor.AddClientACL(target.Source, target.Target, string(target.Protocol), target.Port)
		})
		return b.show(ctx, cb, view)
	}
	return b.show(ctx, cb, b.afterACLChange(b.text(msgACLRemoved)))
}

func (b *Bot) afterACLChange(text string) screen {
	return screen{
		text: text + "\n\n" + b.text(msgACLAfterChange),
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚀 "+b.text(msgButtonDeploy), "dep")},
			[]tg.InlineKeyboardButton{btn("🔐 ACL", "acl"), btn("🏠 "+b.text(msgButtonMenu), "m")},
		),
	}
}

func parseClientACLSpec(value string) (domain.ClientACLProtocol, uint16, MessageID) {
	protocol, rawPort, ok := strings.Cut(strings.ToLower(strings.TrimSpace(value)), "/")
	if !ok || rawPort == "" {
		return "", 0, msgACLSpecFormatError
	}
	if protocol != string(domain.ClientACLTCP) && protocol != string(domain.ClientACLUDP) {
		return "", 0, msgACLSpecProtocolError
	}
	port64, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port64 == 0 {
		return "", 0, msgACLSpecPortError
	}
	return domain.ClientACLProtocol(protocol), uint16(port64), ""
}
