package bot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

func (b *Bot) buildSubs(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	var entries []subEntry
	for _, tunnel := range b.subscriptionTunnels(cfg) {
		entry := subEntry{ID: tunnel.ID, Enabled: tunnel.IsEnabled()}
		path := filepath.Join(b.ConfigDir, "subscriptions", tunnel.ID+".link")
		if content, err := os.ReadFile(path); err == nil {
			if proxy, err := linux.ParseVLESS(strings.TrimSpace(string(content))); err == nil {
				entry.Upstream = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
			} else {
				entry.Upstream = "нечитаемый link-файл"
			}
		}
		if _, err := os.Stat(path + ".last-known-good"); err == nil {
			entry.HasLastGood = true
		}
		entries = append(entries, entry)
	}
	return scr(renderSubs(entries, b.Cfg.Notifications.SubscriptionRefresh))
}

func (b *Bot) routeSubs(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildSubs(ctx))
	case "r":
		if len(args) < 1 {
			return result{toast: "Не указан туннель"}
		}
		return b.startManualRefresh(ctx, cb, args[0])
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
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
		return result{toast: "⏳ Занято: " + busyWith, alert: true}
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
