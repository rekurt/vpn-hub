package bot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

const (
	msgFailureUndoFailed  MessageID = "failure/undo_failed"
	msgFailureUndoDetails MessageID = "failure/undo_details"
)

func renderFailure(l Localizer, what string, err error) screen {
	return screen{
		text:   "⚠️ " + what + ":\n<code>" + esc(err.Error()) + "</code>",
		markup: keyboard(backRow(l)),
	}
}

// revertEdit undoes a configuration change that did not validate, and says so
// when the undo did not work either.
//
// Every caller used to drop the undo's error and report "cancelled" regardless.
// That is a lie an operator acts on: the file is still broken, the next deploy
// fails validation, and nothing said so -- while the screen claimed the change
// had been taken back. Reverting is also the only reason the bot survives a bad
// edit at all, since an unloadable configuration takes the whole UI with it.
func revertEdit(l Localizer, cancelled string, invalid error, undo func() error) screen {
	if err := undo(); err != nil {
		return renderFailure(l, l.Text(msgFailureUndoFailed),
			errors.New(l.Text(msgFailureUndoDetails, invalid, err)))
	}
	return renderFailure(l, cancelled, invalid)
}

// --- Status ----------------------------------------------------------------

const agentUnit = "vpn-hub-agent.service"

func (b *Bot) buildStatus(ctx context.Context) screen {
	view := statusView{Now: b.Now(), HealthEvery: b.Cfg.Notifications.HealthInterval, Health: b.health.list(), DevicesOnline: -1}

	if entries, err := b.deviceEntries(ctx); err == nil {
		view.DevicesTotal = len(entries)
		online := 0
		observed := false
		for _, entry := range entries {
			if entry.Peer != nil {
				observed = true
			}
			if entry.online() {
				online++
			}
		}
		// Zero peers on the interface and zero observations is indistinguishable
		// from "could not look"; claim a count only when something was seen.
		if observed {
			view.DevicesOnline = online
		}
	}

	if state, err := b.Revisions.Load(ctx); errors.Is(err, os.ErrNotExist) {
		// A hub before its first deploy is a legitimate state, not a failure.
	} else if err != nil {
		view.StateErr = err.Error()
	} else {
		view.State = &state
		// Plan is a report, not an action: it shells out to observe the host but
		// changes nothing. Failing here (a workstation, a stopped agent) degrades
		// the screen, not the bot.
		if operations, err := b.Reconciler.Plan(ctx, state); err != nil {
			view.DriftErr = err.Error()
		} else {
			view.Drift = operations
		}
	}

	if pending, armed, err := b.Confirmations.Load(); err == nil && armed {
		view.Pending = &pending
	}

	if unit, err := b.Units.Status(ctx, agentUnit); err != nil {
		view.AgentErr = err.Error()
	} else {
		view.Agent = &unit
	}
	return scr(renderStatus(b.L, view))
}

// --- Routes ----------------------------------------------------------------

func (b *Bot) buildRoutes(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure(b.L, "конфигурация не читается", err)
	}
	state, err := b.Service.BuildDesiredState(cfg)
	if err != nil {
		return renderFailure(b.L, "ревизия не собирается", err)
	}

	var lines []routeLine
	for _, tunnel := range state.Tunnels {
		if tunnel.Role != domain.RolePrivateNetwork {
			continue
		}
		for _, route := range tunnel.Routes {
			lines = append(lines, routeLine{route, tunnel.ID, "приватная сеть"})
		}
		for _, zone := range tunnel.DNSZones {
			lines = append(lines, routeLine{"*." + zone, tunnel.ID, "приватный домен"})
		}
	}

	byEgress := map[string][]string{}
	for _, device := range state.Devices {
		byEgress[device.Egress] = append(byEgress[device.Egress], device.ID)
	}
	egresses := make([]string, 0, len(byEgress))
	for egress := range byEgress {
		egresses = append(egresses, egress)
	}
	sort.Strings(egresses)
	for _, egress := range egresses {
		devices := byEgress[egress]
		sort.Strings(devices)
		lines = append(lines, routeLine{"всё остальное", egress, "по умолчанию для " + strings.Join(devices, ", ")})
	}

	// SOCKS endpoints are the other way traffic is steered; failures here only cost
	// this section -- on a host without an uplink the rest of the picture stands.
	if uplink, err := b.Uplink(ctx); err == nil {
		if plan, err := application.BuildFirewallPlan(state, uplink); err == nil {
			if specs, err := application.BuildEgressSpecs(state, plan, placeholderUpstreams(state)); err == nil {
				for _, spec := range specs {
					if spec.SocksPort == 0 {
						continue
					}
					endpoint := fmt.Sprintf("socks5://%s:%d", hostOf(spec.HostAddress), spec.SocksPort)
					lines = append(lines, routeLine{endpoint, spec.TunnelID, "для отдельного приложения"})
				}
			}
		}
	}
	return scr(renderRoutes(b.L, lines))
}

// placeholderUpstreams supplies layout-only upstreams: which ports exist does not
// depend on a provider's file contents, and the bot may render this screen while a
// provider file is briefly missing.
func placeholderUpstreams(state domain.DesiredState) map[string]domain.Upstream {
	upstreams := make(map[string]domain.Upstream, len(state.Tunnels))
	for _, tunnel := range state.Tunnels {
		upstreams[tunnel.ID] = domain.Upstream{Type: tunnel.Type}
	}
	return upstreams
}

func hostOf(address string) string {
	if index := strings.IndexByte(address, '/'); index >= 0 {
		return address[:index]
	}
	return address
}

// --- Logs ------------------------------------------------------------------

func (b *Bot) buildLogsMenu(ctx context.Context) screen {
	units, err := b.Units.ListMatching(ctx, "vpn-hub-*")
	if err != nil {
		return renderFailure(b.L, "список юнитов недоступен", err)
	}
	return scr(renderLogsMenu(b.L, units))
}

func (b *Bot) routeLogs(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildLogsMenu(ctx))
	case "u":
		if len(args) < 1 {
			return result{toast: "Не указан юнит"}
		}
		unit := args[0]
		tail, err := b.Journal.Tail(ctx, unit, 50)
		if err != nil {
			return b.show(ctx, cb, renderFailure(b.L, "журнал недоступен", err))
		}
		return b.show(ctx, cb, scr(renderLogTail(b.L, unit, tail)))
	case "f":
		if len(args) < 1 {
			return result{toast: "Не указан юнит"}
		}
		unit := args[0]
		tail, err := b.Journal.Tail(ctx, unit, 500)
		if err != nil {
			return result{toast: "Журнал недоступен: " + err.Error(), alert: true}
		}
		name := strings.TrimSuffix(unit, ".service") + ".log.txt"
		if _, err := b.API.SendDocument(ctx, b.Cfg.AdminID, name, []byte(tail), "📜 "+esc(unit)+", последние 500 строк"); err != nil {
			return result{toast: "Не удалось отправить файл", alert: true}
		}
		return result{toast: "Отправил файлом"}
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// --- Host ------------------------------------------------------------------

func (b *Bot) buildHost(ctx context.Context) screen {
	view := hostView{}
	if snapshot, err := b.Host(); err != nil {
		view.Err = err.Error()
	} else {
		view.Snapshot = snapshot
	}

	// The installed units first, then whatever transient per-tunnel services exist
	// right now; ListMatching answers with the current truth.
	for _, unit := range []string{agentUnit, "vpn-hub-bot.service"} {
		if status, err := b.Units.Status(ctx, unit); err == nil {
			view.Units = append(view.Units, status)
		}
	}
	if transient, err := b.Units.ListMatching(ctx, "vpn-hub-proxy-*"); err == nil {
		view.Units = append(view.Units, transient...)
	}
	if transient, err := b.Units.ListMatching(ctx, "vpn-hub-openvpn-*"); err == nil {
		view.Units = append(view.Units, transient...)
	}
	if transient, err := b.Units.ListMatching(ctx, "vpn-hub-socks-*"); err == nil {
		view.Units = append(view.Units, transient...)
	}
	return scr(renderHost(b.L, view))
}

func (b *Bot) routeHost(ctx context.Context, cb *tg.CallbackQuery, action string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildHost(ctx))
	case "ra":
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			"Перезапустить агента? На время рестарта хост перестаёт сходиться (туннели продолжают работать).",
			"host:ra!", "host")))
	case "ra!":
		if err := b.Units.Restart(ctx, agentUnit); err != nil {
			return result{toast: "Не удалось: " + err.Error(), alert: true}
		}
		outcome := b.show(ctx, cb, b.buildHost(ctx))
		outcome.toast = "🔁 Агент перезапущен"
		return outcome
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// --- Settings --------------------------------------------------------------

func (b *Bot) buildSettings() screen {
	return scr(renderSettings(b.L, b.alerts.snapshot(), b.Cfg.Notifications))
}

func (b *Bot) routeSettings(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildSettings())
	case "t":
		if len(args) < 1 {
			return result{toast: "Не указана категория"}
		}
		enabled := b.alerts.toggle(args[0])
		b.saveAlertSettings(ctx)
		outcome := b.show(ctx, cb, b.buildSettings())
		if enabled {
			outcome.toast = "🔔 Включено"
		} else {
			outcome.toast = "🔕 Выключено"
		}
		return outcome
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// loadAlertSettings restores the saved switches over the defaults; a failure keeps
// the defaults, which is the safe direction -- everything on.
func (b *Bot) loadAlertSettings(ctx context.Context) {
	if b.Settings == nil {
		return
	}
	saved, err := b.Settings.Load(ctx)
	if err != nil {
		b.logf("load bot settings: %v", err)
		return
	}
	for key, value := range saved.Alerts {
		b.alerts.set(key, value)
	}
}

func (b *Bot) saveAlertSettings(ctx context.Context) {
	if b.Settings == nil {
		return
	}
	if err := b.Settings.Save(ctx, runtimeadapter.BotSettings{Alerts: b.alerts.snapshot()}); err != nil {
		b.logf("save bot settings: %v", err)
	}
}
