package bot

import (
	"context"
	"strconv"
	"sync"
	"time"

	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

// compileNext runs the same pipeline as `hubctl deploy`: validate, drop revoked
// devices, compile the revision.
func (b *Bot) compileNext(ctx context.Context) (domain.DesiredState, []string, error) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return domain.DesiredState{}, nil, err
	}
	revoked, err := b.Revocations.Load(ctx)
	if err != nil {
		return domain.DesiredState{}, nil, err
	}
	state, err := b.Service.BuildDesiredState(application.RemoveRevoked(cfg, revoked))
	return state, revoked, err
}

func (b *Bot) buildDeployPreview(ctx context.Context) screen {
	next, revoked, err := b.compileNext(ctx)
	if err != nil {
		return renderFailure("деплой невозможен", err)
	}
	view := deployView{Next: next, Revoked: revoked}
	if current, err := b.Revisions.Load(ctx); err == nil {
		view.Current = &current
		view.Changes = diffStates(&current, next)
	}
	return scr(renderDeployPreview(view))
}

func (b *Bot) routeDeploy(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildDeployPreview(ctx))
	case "arm":
		if len(args) < 1 {
			return result{toast: "Нет ревизии"}
		}
		return b.show(ctx, cb, scr(renderConfirmWithinChoice(args[0])))
	case "go":
		if len(args) < 2 {
			return result{toast: "Нет параметров"}
		}
		seconds, err := strconv.Atoi(args[0])
		if err != nil || seconds <= 0 {
			return result{toast: "Кривой таймаут"}
		}
		return b.applyDeploy(ctx, cb, args[1], time.Duration(seconds)*time.Second)
	case "now":
		if len(args) < 1 {
			return result{toast: "Нет ревизии"}
		}
		return b.show(ctx, cb, scr(renderConfirm(
			"Применить <b>без страховки</b>? Если ревизия отрежет доступ, чинить придётся руками через консоль провайдера.",
			"dep:now!:"+args[0], "dep")))
	case "now!":
		if len(args) < 1 {
			return result{toast: "Нет ревизии"}
		}
		return b.applyDeploy(ctx, cb, args[0], 0)
	case "ok":
		return b.confirmDeploy(ctx, cb)
	case "rb":
		return b.show(ctx, cb, scr(renderConfirm(
			"Вернуть предыдущую ревизию? Агент применит её на ближайшем проходе.",
			"dep:rb!", "dep")))
	case "rb!":
		return b.rollbackDeploy(ctx, cb)
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// applyDeploy is `hubctl deploy --dry-run=false [--confirm-within N]` in-process.
func (b *Bot) applyDeploy(ctx context.Context, cb *tg.CallbackQuery, expectedRevision string, confirmWithin time.Duration) result {
	release, busyWith, ok := b.gate.Acquire("деплой")
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	state, _, err := b.compileNext(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("деплой невозможен", err))
	}
	// The button was rendered against a specific revision; applying whatever the
	// config says *now* would deploy something the admin never previewed.
	if state.Revision != expectedRevision {
		outcome := b.show(ctx, cb, b.buildDeployPreview(ctx))
		outcome.toast = "Конфигурация изменилась — превью обновлено, посмотрите ещё раз"
		outcome.alert = true
		return outcome
	}

	b.self.mark(b.Now())
	armed := false
	if confirmWithin > 0 {
		if armed, err = b.Confirmations.Arm(ctx, confirmWithin, state.Revision); err != nil {
			return b.show(ctx, cb, renderFailure("страховка не взвелась", err))
		}
	}
	if err := b.Service.Save(ctx, state); err != nil {
		// Arm ran but Save did not: a pending confirmation now points at a revision
		// that was never written, and the agent would "roll back" to the already
		// active one at the deadline. Clear it so nothing is armed over nothing.
		if armed {
			_ = b.Confirmations.Confirm()
		}
		return b.show(ctx, cb, renderFailure("ревизия не сохранилась", err))
	}

	switch {
	case confirmWithin > 0 && !armed:
		// Said plainly, as in the CLI: believing a rollback is watching when none is
		// armed is worse than knowing there is none.
		return b.show(ctx, cb, screen{
			text:   "✅ Ревизия <code>" + esc(state.Revision) + "</code> сохранена. Отката не будет: это первый деплой, возвращаться не к чему. Агент применит её на ближайшем проходе.",
			markup: keyboard(backRow),
		})
	case confirmWithin > 0:
		outcome := b.show(ctx, cb, scr(renderCountdown(state.Revision, confirmWithin)))
		if cb != nil && cb.Message != nil {
			b.startCountdown(ctx, cb.Message.Chat.ID, cb.Message.ID, state.Revision)
		}
		outcome.toast = "Применено, жду подтверждения"
		return outcome
	default:
		return b.show(ctx, cb, screen{
			text:   "⚡ Ревизия <code>" + esc(state.Revision) + "</code> сохранена без страховки. Агент применит её на ближайшем проходе.",
			markup: keyboard(backRow),
		})
	}
}

func (b *Bot) confirmDeploy(ctx context.Context, cb *tg.CallbackQuery) result {
	// Serialize with the other confirmation-state mutators (rollback, scheduled
	// refresh) through the same gate rollbackDeploy takes: both write Confirmations,
	// and confirming while a rollback is in flight must not race.
	release, busyWith, ok := b.gate.Acquire("подтверждение")
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	pending, armed, err := b.Confirmations.Load()
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if !armed {
		return result{toast: "Нечего подтверждать", alert: true}
	}
	b.self.mark(b.Now())
	if err := b.Confirmations.Confirm(); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	b.deploy.stop()
	outcome := b.show(ctx, cb, screen{
		text:   "✅ Ревизия <code>" + esc(pending.Revision) + "</code> подтверждена, страховка снята.",
		markup: keyboard(backRow),
	})
	outcome.toast = "Подтверждено"
	return outcome
}

func (b *Bot) rollbackDeploy(ctx context.Context, cb *tg.CallbackQuery) result {
	release, busyWith, ok := b.gate.Acquire("откат")
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	b.self.mark(b.Now())
	state, err := b.Confirmations.Rollback(ctx)
	if err != nil {
		return result{toast: err.Error(), alert: true}
	}
	b.deploy.stop()
	outcome := b.show(ctx, cb, screen{
		text:   "↩️ Восстановлена ревизия <code>" + esc(state.Revision) + "</code>; агент применит её на ближайшем проходе.",
		markup: keyboard(backRow),
	})
	outcome.toast = "Откатил"
	return outcome
}

// --- countdown -------------------------------------------------------------

// deployWatch owns the live countdown editor; there is at most one.
type deployWatch struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (d *deployWatch) replace(cancel context.CancelFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		d.cancel()
	}
	d.cancel = cancel
}

func (d *deployWatch) stop() {
	d.replace(nil)
}

// resumePendingDeploy reattaches a countdown after a restart. The bot restarts on
// every deploy, so an armed-and-unconfirmed revision is the normal state right
// after applying one: without this the old countdown message freezes and the
// deadline passes with no warning until the agent's auto-rollback line appears.
func (b *Bot) resumePendingDeploy(ctx context.Context) {
	pending, armed, err := b.Confirmations.Load()
	if err != nil || !armed {
		return
	}
	left := pending.Deadline.Sub(b.Now())
	var view screen
	if left > 0 {
		view = scr(renderCountdown(pending.Revision, left))
	} else {
		view = scr(renderCountdownOverdue(pending.Revision))
	}
	message, err := b.API.SendMessage(ctx, b.Cfg.AdminID,
		"↻ Возобновлён отсчёт после перезапуска бота.\n\n"+view.text, view.markup)
	if err != nil {
		b.logf("resume countdown: %v", err)
		return
	}
	b.startCountdown(ctx, message.Chat.ID, message.ID, pending.Revision)
}

// startCountdown keeps the armed-deploy message alive: remaining time while the
// clock runs, and the actual outcome once the pending state resolves -- whether it
// was the bot, the CLI or the agent's auto-rollback that resolved it.
func (b *Bot) startCountdown(ctx context.Context, chatID, messageID int64, revision string) {
	watchCtx, cancel := context.WithCancel(ctx)
	b.deploy.replace(cancel)

	b.spawn("countdown-"+revision, func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
			}

			pending, armed, err := b.Confirmations.Load()
			if err != nil {
				b.logf("countdown: %v", err)
				continue
			}
			switch {
			case armed && pending.Revision != revision:
				// Another deploy took over; its own countdown speaks now.
				return
			case armed:
				left := pending.Deadline.Sub(b.Now())
				var view screen
				if left > 0 {
					view = scr(renderCountdown(revision, left))
				} else {
					view = scr(renderCountdownOverdue(revision))
				}
				if err := b.API.EditMessageText(watchCtx, chatID, messageID, view.text, view.markup); err != nil {
					b.logf("countdown edit: %v", err)
				}
			default:
				// Resolved. The revision store says how.
				text := "✅ Ревизия <code>" + esc(revision) + "</code> подтверждена."
				if state, err := b.Revisions.Load(watchCtx); err == nil && state.Revision != revision {
					text = "⛔ Ревизия <code>" + esc(revision) + "</code> не подтверждена: восстановлена <code>" + esc(state.Revision) + "</code>."
				}
				if err := b.API.EditMessageText(watchCtx, chatID, messageID, text, keyboard(backRow)); err != nil {
					b.logf("countdown edit: %v", err)
				}
				return
			}
		}
	})
}
