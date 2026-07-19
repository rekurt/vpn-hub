package bot

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-hub/internal/adapters/health"
	"vpn-hub/internal/adapters/linux"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

func (b *Bot) subscriptionTunnels(cfg domain.Config) []domain.Tunnel {
	var tunnels []domain.Tunnel
	for _, tunnel := range cfg.Tunnels {
		if tunnel.Source.Kind == domain.SourceSubscription {
			tunnels = append(tunnels, tunnel)
		}
	}
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })
	return tunnels
}

func (b *Bot) subEntryFor(tunnel domain.Tunnel) subEntry {
	entry := subEntry{ID: tunnel.ID, Enabled: tunnel.IsEnabled(), Health: b.health.get(tunnel.ID)}
	if current, hasCurrent, hasPrevious := b.Upstreams.Current(tunnel.ID); hasCurrent {
		entry.Upstream = fmt.Sprintf("%s:%d", current.Server, current.Port)
		entry.LastGood = hasPrevious
	} else if hasPrevious {
		entry.LastGood = true
	}
	return entry
}

func (b *Bot) buildSubs(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	var entries []subEntry
	for _, tunnel := range b.subscriptionTunnels(cfg) {
		entries = append(entries, b.subEntryFor(tunnel))
	}
	return scr(renderSubs(entries, b.Cfg.Notifications.SubscriptionRefresh))
}

func (b *Bot) buildSubCard(ctx context.Context, tunnelID string) screen {
	tunnel, err := b.subscriptionTunnel(ctx, tunnelID)
	if err != nil {
		return renderFailure("подписка не найдена", err)
	}
	return scr(renderSubCard(b.subEntryFor(tunnel)))
}

func (b *Bot) subscriptionTunnel(ctx context.Context, tunnelID string) (domain.Tunnel, error) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return domain.Tunnel{}, err
	}
	for _, tunnel := range b.subscriptionTunnels(cfg) {
		if tunnel.ID == tunnelID {
			return tunnel, nil
		}
	}
	return domain.Tunnel{}, fmt.Errorf("туннель %q не подписочный", tunnelID)
}

func (b *Bot) routeSubs(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	if action != "" && len(args) < 1 {
		return result{toast: "Не указан туннель"}
	}
	switch action {
	case "":
		return b.show(ctx, cb, b.buildSubs(ctx))
	case "c":
		return b.show(ctx, cb, b.buildSubCard(ctx, args[0]))
	case "r":
		return b.startManualRefresh(ctx, cb, args[0])
	case "cand":
		page := 0
		if len(args) > 1 {
			page, _ = strconv.Atoi(args[1])
		}
		return b.showCandidates(ctx, cb, args[0], page)
	case "pick":
		if len(args) < 2 {
			return result{toast: "Нет кандидата"}
		}
		index, err := strconv.Atoi(args[1])
		if err != nil {
			return result{toast: "Кривой индекс"}
		}
		return b.pickCandidate(ctx, cb, args[0], index)
	case "lkg":
		return b.show(ctx, cb, scr(renderConfirm(
			fmt.Sprintf("Вернуть предыдущий upstream для <b>%s</b>? Текущий станет last-known-good.", esc(args[0])),
			"sub:lkg!:"+args[0], "sub:c:"+args[0])))
	case "lkg!":
		return b.restoreLastGood(ctx, cb, args[0])
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// --- last-known-good -------------------------------------------------------

func (b *Bot) restoreLastGood(ctx context.Context, cb *tg.CallbackQuery, tunnelID string) result {
	release, busyWith, ok := b.gate.Acquire("возврат last-known-good " + tunnelID)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	restored, err := b.Upstreams.Restore(tunnelID)
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}
	warning := b.agentInactiveWarning(ctx)
	text := fmt.Sprintf("↩️ <b>%s</b>: восстановлен upstream <code>%s:%d</code>.\nАгент подхватит его на ближайшем проходе; прежний сохранён как last-known-good.",
		esc(tunnelID), esc(restored.Server), restored.Port)
	if warning != "" {
		text += "\n" + warning
	}
	outcome := b.show(ctx, cb, screen{text: text, markup: keyboard(
		[]tg.InlineKeyboardButton{btn("📡 К подписке", "sub:c:"+tunnelID), btn("📊 Статус", "st")},
	)})
	outcome.toast = "Восстановлен"
	return outcome
}

// --- candidates ------------------------------------------------------------

// candidateCache keeps the last fetched list per tunnel: a callback carries an
// index, and the index must point into the exact list the buttons were built from.
type candidateCache struct {
	mu       sync.Mutex
	byTunnel map[string][]domain.ProxyTunnel
}

func (c *candidateCache) put(tunnelID string, candidates []domain.ProxyTunnel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byTunnel == nil {
		c.byTunnel = map[string][]domain.ProxyTunnel{}
	}
	c.byTunnel[tunnelID] = candidates
}

func (c *candidateCache) get(tunnelID string) []domain.ProxyTunnel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byTunnel[tunnelID]
}

// showCandidates renders the provider's candidate list. Nothing on the host is
// touched, so no gate. Cached pages render inline; page 0 (or an empty cache) needs
// a network fetch of up to 15s, which runs in the background so the update loop
// keeps answering.
func (b *Bot) showCandidates(ctx context.Context, cb *tg.CallbackQuery, tunnelID string, page int) result {
	tunnel, err := b.subscriptionTunnel(ctx, tunnelID)
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}

	if candidates := b.candidates.get(tunnelID); page > 0 && len(candidates) > 0 {
		return b.show(ctx, cb, b.candidatesScreen(tunnelID, candidates, page))
	}

	b.show(ctx, cb, screen{text: "📋 Загружаю список кандидатов…"})
	b.spawn("candidates-"+tunnelID, func() {
		edit := func(view screen) {
			if cb.Message == nil {
				b.sendScreen(ctx, view)
				return
			}
			if err := b.API.EditMessageText(ctx, cb.Message.Chat.ID, cb.Message.ID, view.text, view.markup); err != nil {
				b.logf("candidates edit: %v", err)
			}
		}

		payload, err := b.Fetch(ctx, tunnel.Source.Value)
		if err != nil {
			edit(renderFailure("подписка не скачалась", err))
			return
		}
		candidates, err := b.Parse(payload)
		if err != nil {
			edit(renderFailure("подписка не разобралась", err))
			return
		}
		if len(candidates) == 0 {
			edit(renderFailure("в подписке пусто", fmt.Errorf("провайдер не отдал ни одного пригодного кандидата")))
			return
		}
		b.candidates.put(tunnelID, candidates)
		edit(b.candidatesScreen(tunnelID, candidates, 0))
	})
	return result{}
}

func (b *Bot) candidatesScreen(tunnelID string, candidates []domain.ProxyTunnel, page int) screen {
	current := ""
	if active, hasCurrent, _ := b.Upstreams.Current(tunnelID); hasCurrent {
		current = fmt.Sprintf("%s:%d", active.Server, active.Port)
	}
	return scr(renderCandidates(tunnelID, candidates, page, current))
}

// pickCandidate proves one chosen candidate and promotes it only when it carried
// traffic -- the same safety the automatic refresh has, minus the "first that
// works" part: here the admin picks which one is worth the wait.
func (b *Bot) pickCandidate(ctx context.Context, cb *tg.CallbackQuery, tunnelID string, index int) result {
	tunnel, err := b.subscriptionTunnel(ctx, tunnelID)
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}
	candidates := b.candidates.get(tunnelID)
	if index < 0 || index >= len(candidates) {
		return result{toast: "Список устарел — откройте кандидатов заново", alert: true}
	}
	candidate := candidates[index]

	release, busyWith, ok := b.gate.Acquire(fmt.Sprintf("проверка кандидата %s:%d", candidate.Server, candidate.Port))
	if !ok {
		return busyResult(busyWith)
	}

	message, err := b.API.SendMessage(ctx, b.Cfg.AdminID,
		fmt.Sprintf("🧪 Проверяю <code>%s:%d</code> в изолированном namespace…", esc(candidate.Server), candidate.Port), nil)
	if err != nil {
		release()
		return result{toast: "Не удалось начать: " + err.Error(), alert: true}
	}

	b.spawn("pick-"+tunnelID, func() {
		defer release()
		edit := func(view screen) {
			if err := b.API.EditMessageText(ctx, message.Chat.ID, message.ID, view.text, view.markup); err != nil {
				b.logf("pick edit: %v", err)
			}
		}

		uplink, err := b.Uplink(ctx)
		if err != nil {
			edit(renderFailure("не определился uplink", err))
			return
		}
		if err := b.Prove(ctx, candidate, uplink); err != nil {
			edit(screen{
				text: fmt.Sprintf("❌ <code>%s:%d</code> не пропустил трафик:\n<code>%s</code>\n\nДействующий upstream не тронут.",
					esc(candidate.Server), candidate.Port, esc(err.Error())),
				markup: keyboard([]tg.InlineKeyboardButton{btn("📋 К кандидатам", "sub:cand:"+tunnelID), btn("📡 К подписке", "sub:c:"+tunnelID)}),
			})
			return
		}
		if err := b.Upstreams.Write(ctx, tunnel, candidate); err != nil {
			edit(renderFailure("кандидат прошёл проверку, но не записался", err))
			return
		}
		edit(scr(renderRefreshResult(tunnelID, candidate, nil, b.agentInactiveWarning(ctx))))
	})
	return result{toast: "Проверяю"}
}

// startManualRefresh launches the prove-and-promote flow in the background: the
// canary can take minutes, and the chat stays alive while it runs, watching the
// progress message change.
func (b *Bot) startManualRefresh(ctx context.Context, cb *tg.CallbackQuery, tunnelID string) result {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("конфигурация не читается", err))
	}
	var subject domain.Tunnel
	for _, tunnel := range b.subscriptionTunnels(cfg) {
		if tunnel.ID == tunnelID {
			subject = tunnel
		}
	}
	if subject.ID == "" {
		return result{toast: "Это не подписочный туннель", alert: true}
	}

	release, busyWith, ok := b.gate.Acquire("обновление подписки " + tunnelID)
	if !ok {
		return busyResult(busyWith)
	}

	message, err := b.API.SendMessage(ctx, b.Cfg.AdminID,
		"📡 <b>"+esc(tunnelID)+"</b>: получаю подписку…", nil)
	if err != nil {
		release()
		return result{toast: "Не удалось начать: " + err.Error(), alert: true}
	}

	b.spawn("refresh-"+tunnelID, func() {
		defer release()
		chosen, rejected, err := b.Refresh(ctx, subject, b.progressEditor(ctx, message.Chat.ID, message.ID, tunnelID))
		var view screen
		if err != nil {
			view = scr(renderRefreshFailure(tunnelID, rejected, err.Error()))
		} else {
			view = scr(renderRefreshResult(tunnelID, chosen, rejected, b.agentInactiveWarning(ctx)))
		}
		if err := b.API.EditMessageText(ctx, message.Chat.ID, message.ID, view.text, view.markup); err != nil {
			b.logf("refresh edit: %v", err)
		}
	})
	return result{toast: "Запустил"}
}

// agentInactiveWarning names the one situation where "the agent picks it up" is a
// lie worth flagging: nothing applies while the agent is down.
func (b *Bot) agentInactiveWarning(ctx context.Context) string {
	unit, err := b.Units.Status(ctx, agentUnit)
	if err != nil || unit.Active == "active" {
		return ""
	}
	return "⚠️ Агент сейчас не работает (" + esc(unit.Active) + ") — изменение не применится, пока он не запустится."
}

// progressEditor edits the progress message as candidates are tried, coalescing to
// one edit per couple of seconds -- Telegram rate-limits edits, and a subscription
// can carry dozens of candidates.
func (b *Bot) progressEditor(ctx context.Context, chatID, messageID int64, tunnelID string) func(tried, total int, rejected []string) {
	var lastEdit time.Time
	return func(tried, total int, rejected []string) {
		now := b.Now()
		if now.Sub(lastEdit) < 2*time.Second {
			return
		}
		lastEdit = now

		var text strings.Builder
		fmt.Fprintf(&text, "📡 <b>%s</b>: проверяю кандидата %d из %d в изолированном namespace…\n", esc(tunnelID), tried, total)
		appendRejections(&text, rejected)
		if err := b.API.EditMessageText(ctx, chatID, messageID, text.String(), nil); err != nil {
			b.logf("progress edit: %v", err)
		}
	}
}

// canaryRefresh is the production refreshFunc: the same fetch → parse → prove →
// promote pipeline as `hubctl subscription refresh`, with the canary driven
// candidate by candidate so progress can be reported.
func (b *Bot) canaryRefresh(ctx context.Context, tunnel domain.Tunnel, progress func(tried, total int, rejected []string)) (domain.ProxyTunnel, []string, error) {
	uplink, err := b.Uplink(ctx)
	if err != nil {
		return domain.ProxyTunnel{}, nil, err
	}
	canary := linux.Canary{Egress: linux.Egress{SecretsDir: b.RuntimeDir}}

	return application.SubscriptionRefresher{
		Fetch: health.HTTPSSubscriptionFetcher{},
		Parse: linux.ParseSubscription,
		Prove: func(ctx context.Context, candidates []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			var reasons []string
			for index, candidate := range candidates {
				if progress != nil {
					progress(index+1, len(candidates), reasons)
				}
				err := canary.Try(ctx, candidate, uplink)
				if err == nil {
					canary.Discard(ctx)
					return candidate, reasons, nil
				}
				reasons = append(reasons, fmt.Sprintf("%s:%d: %v", candidate.Server, candidate.Port, err))
				if ctx.Err() != nil {
					break
				}
			}
			canary.Discard(ctx)
			return domain.ProxyTunnel{}, reasons, fmt.Errorf("ни один кандидат не пропустил трафик")
		},
		Store: linux.UpstreamFile{Dir: b.ConfigDir},
	}.Refresh(ctx, tunnel)
}

// scheduleRefreshes is the timer the systemd unit used to be: every interval, each
// subscription tunnel is refreshed through the same gate as everything else, so a
// scheduled run can never collide with a manual one over the singleton canary.
func (b *Bot) scheduleRefreshes(ctx context.Context) {
	ticker := time.NewTicker(b.Cfg.Notifications.SubscriptionRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cfg, err := b.Service.LoadAndValidate(ctx)
		if err != nil {
			b.logf("scheduled refresh: %v", err)
			continue
		}
		for _, tunnel := range b.subscriptionTunnels(cfg) {
			if !tunnel.IsEnabled() {
				continue
			}
			b.refreshScheduled(ctx, tunnel)
		}
	}
}

func (b *Bot) refreshScheduled(ctx context.Context, tunnel domain.Tunnel) {
	release, busyWith, ok := b.gate.Acquire("плановое обновление подписки " + tunnel.ID)
	if !ok {
		// Not an error: the next tick retries, and whatever holds the gate was
		// started by the admin on purpose.
		b.logf("scheduled refresh of %s skipped: busy with %s", tunnel.ID, busyWith)
		return
	}
	defer release()

	chosen, rejected, err := b.Refresh(ctx, tunnel, nil)
	if err != nil {
		view := scr(renderRefreshFailure(tunnel.ID, rejected, err.Error()))
		b.emit(event{category: "subscription", text: "🕕 Плановое обновление:\n\n" + view.text, markup: view.markup})
		return
	}
	view := scr(renderRefreshResult(tunnel.ID, chosen, rejected, b.agentInactiveWarning(ctx)))
	b.emit(event{category: "subscription", text: "🕕 Плановое обновление:\n\n" + view.text, markup: view.markup})
}
