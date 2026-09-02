package bot

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

// deployment is the shared pipeline `hubctl deploy` drives too; building it here
// keeps the Bot struct free of one more field.
func (b *Bot) deployment() application.Deployment {
	return application.Deployment{
		Service:       b.Service,
		Revocations:   b.Revocations,
		Confirmations: b.Confirmations,
	}
}

// compileNext runs the same pipeline as `hubctl deploy`: validate, drop revoked
// devices, compile the revision.
func (b *Bot) compileNext(ctx context.Context) (domain.DesiredState, []string, error) {
	return b.deployment().Compile(ctx)
}

func (b *Bot) buildDeployPreview(ctx context.Context) screen {
	next, revoked, err := b.compileNext(ctx)
	if err != nil {
		return renderFailure(b.L, "деплой невозможен", err)
	}
	view := deployView{Next: next, Revoked: revoked}
	if current, err := b.Revisions.Load(ctx); err == nil {
		view.Current = &current
		view.Changes = diffStates(b.L, &current, next)
	}
	return scr(renderDeployPreview(b.L, view))
}

func (b *Bot) routeDeploy(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildDeployPreview(ctx))
	case "arm":
		if len(args) < 1 {
			return result{toast: "Нет ревизии"}
		}
		return b.show(ctx, cb, scr(renderConfirmWithinChoice(b.L, args[0])))
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
		return b.show(ctx, cb, scr(renderConfirm(b.L,
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
		return b.show(ctx, cb, scr(renderConfirm(b.L,
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
	release, busy := b.claim(newOperation(msgOperationDeploy))
	if busy != nil {
		return *busy
	}
	defer release()

	state, _, err := b.compileNext(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, "деплой невозможен", err))
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
	applied, err := b.deployment().Apply(ctx, state, confirmWithin)
	if err != nil {
		var stage application.DeployError
		if errors.As(err, &stage) && stage.Stage == application.DeployStageArm {
			return b.show(ctx, cb, renderFailure(b.L, "страховка не взвелась", stage.Err))
		}
		return b.show(ctx, cb, renderFailure(b.L, "ревизия не сохранилась", err))
	}
	armed := applied.Armed

	switch {
	case confirmWithin > 0 && !armed:
		// Said plainly, as in the CLI: believing a rollback is watching when none is
		// armed is worse than knowing there is none.
		return b.show(ctx, cb, screen{
			text:   "✅ Ревизия <code>" + esc(state.Revision) + "</code> сохранена. Отката не будет: это первый деплой, возвращаться не к чему. Агент применит её на ближайшем проходе.",
			markup: keyboard(backRow(b.L)),
		})
	case confirmWithin > 0:
		outcome := b.show(ctx, cb, scr(renderCountdown(b.L, state.Revision, confirmWithin)))
		if cb != nil && cb.Message != nil {
			b.startCountdown(ctx, cb.Message.Chat.ID, cb.Message.ID, state.Revision)
		}
		outcome.toast = "Применено, жду подтверждения"
		return outcome
	default:
		return b.show(ctx, cb, screen{
			text:   "⚡ Ревизия <code>" + esc(state.Revision) + "</code> сохранена без страховки. Агент применит её на ближайшем проходе.",
			markup: keyboard(backRow(b.L)),
		})
	}
}

func (b *Bot) confirmDeploy(ctx context.Context, cb *tg.CallbackQuery) result {
	// Serialize with the other confirmation-state mutators (rollback, scheduled
	// refresh) through the same gate rollbackDeploy takes: both write Confirmations,
	// and confirming while a rollback is in flight must not race.
	release, busy := b.claim(newOperation(msgOperationDeployConfirm))
	if busy != nil {
		return *busy
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
		markup: keyboard(backRow(b.L)),
	})
	outcome.toast = "Подтверждено"
	return outcome
}

func (b *Bot) rollbackDeploy(ctx context.Context, cb *tg.CallbackQuery) result {
	release, busy := b.claim(newOperation(msgOperationDeployRollback))
	if busy != nil {
		return *busy
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
		markup: keyboard(backRow(b.L)),
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
		view = scr(renderCountdown(b.L, pending.Revision, left))
	} else {
		view = scr(renderCountdownOverdue(b.L, pending.Revision))
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
					view = scr(renderCountdown(b.L, revision, left))
				} else {
					view = scr(renderCountdownOverdue(b.L, revision))
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
				if err := b.API.EditMessageText(watchCtx, chatID, messageID, text, keyboard(backRow(b.L))); err != nil {
					b.logf("countdown edit: %v", err)
				}
				return
			}
		}
	})
}
