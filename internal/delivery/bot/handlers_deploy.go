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

const (
	msgFailureDeployImpossible   MessageID = "failure/deploy_impossible"
	msgDeployRevisionRequired    MessageID = "deploy/revision_required"
	msgDeployParametersRequired  MessageID = "deploy/parameters_required"
	msgDeployTimeoutInvalid      MessageID = "deploy/timeout_invalid"
	msgDeployImmediateConfirm    MessageID = "deploy/immediate_confirm"
	msgDeployRollbackConfirm     MessageID = "deploy/rollback_confirm"
	msgDeployPreviewStale        MessageID = "deploy/preview_stale"
	msgFailureDeployArm          MessageID = "failure/deploy_arm"
	msgFailureRevisionSave       MessageID = "failure/revision_save"
	msgDeployFirstNoRollback     MessageID = "deploy/first_no_rollback"
	msgDeployAppliedAwaiting     MessageID = "deploy/applied_awaiting"
	msgDeployImmediateSaved      MessageID = "deploy/immediate_saved"
	msgDeployNothingToConfirm    MessageID = "deploy/nothing_to_confirm"
	msgFailureDeployState        MessageID = "failure/deploy_state"
	msgDeployConfirmed           MessageID = "deploy/confirmed"
	msgDeployConfirmedToast      MessageID = "deploy/confirmed_toast"
	msgDeployRolledBack          MessageID = "deploy/rolled_back"
	msgDeployRolledBackToast     MessageID = "deploy/rolled_back_toast"
	msgDeployCountdownResumed    MessageID = "deploy/countdown_resumed"
	msgDeployCountdownConfirmed  MessageID = "deploy/countdown_confirmed"
	msgDeployCountdownRolledBack MessageID = "deploy/countdown_rolled_back"
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
		return renderFailure(b.L, b.text(msgFailureDeployImpossible), err)
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
			return result{toast: b.text(msgDeployRevisionRequired)}
		}
		return b.show(ctx, cb, scr(renderConfirmWithinChoice(b.L, args[0])))
	case "go":
		if len(args) < 2 {
			return result{toast: b.text(msgDeployParametersRequired)}
		}
		seconds, err := strconv.Atoi(args[0])
		if err != nil || seconds <= 0 {
			return result{toast: b.text(msgDeployTimeoutInvalid)}
		}
		return b.applyDeploy(ctx, cb, args[1], time.Duration(seconds)*time.Second)
	case "now":
		if len(args) < 1 {
			return result{toast: b.text(msgDeployRevisionRequired)}
		}
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			b.text(msgDeployImmediateConfirm),
			"dep:now!:"+args[0], "dep")))
	case "now!":
		if len(args) < 1 {
			return result{toast: b.text(msgDeployRevisionRequired)}
		}
		return b.applyDeploy(ctx, cb, args[0], 0)
	case "ok":
		return b.confirmDeploy(ctx, cb)
	case "rb":
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			b.text(msgDeployRollbackConfirm),
			"dep:rb!", "dep")))
	case "rb!":
		return b.rollbackDeploy(ctx, cb)
	default:
		return result{toast: b.text(msgUnknownButton)}
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
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureDeployImpossible), err))
	}
	// The button was rendered against a specific revision; applying whatever the
	// config says *now* would deploy something the admin never previewed.
	if state.Revision != expectedRevision {
		outcome := b.show(ctx, cb, b.buildDeployPreview(ctx))
		outcome.toast = b.text(msgDeployPreviewStale)
		outcome.alert = true
		return outcome
	}

	b.self.mark(b.Now())
	applied, err := b.deployment().Apply(ctx, state, confirmWithin)
	if err != nil {
		var stage application.DeployError
		if errors.As(err, &stage) && stage.Stage == application.DeployStageArm {
			return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureDeployArm), stage.Err))
		}
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureRevisionSave), err))
	}
	armed := applied.Armed

	switch {
	case confirmWithin > 0 && !armed:
		// Said plainly, as in the CLI: believing a rollback is watching when none is
		// armed is worse than knowing there is none.
		return b.show(ctx, cb, screen{
			text:   b.text(msgDeployFirstNoRollback, esc(state.Revision)),
			markup: keyboard(backRow(b.L)),
		})
	case confirmWithin > 0:
		outcome := b.show(ctx, cb, scr(renderCountdown(b.L, state.Revision, confirmWithin)))
		if cb != nil && cb.Message != nil {
			b.startCountdown(ctx, cb.Message.Chat.ID, cb.Message.ID, state.Revision)
		}
		outcome.toast = b.text(msgDeployAppliedAwaiting)
		return outcome
	default:
		return b.show(ctx, cb, screen{
			text:   b.text(msgDeployImmediateSaved, esc(state.Revision)),
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
		b.logf("load deploy confirmation: %v", err)
		return result{toast: b.text(msgFailureDeployState), alert: true}
	}
	if !armed {
		return result{toast: b.text(msgDeployNothingToConfirm), alert: true}
	}
	b.self.mark(b.Now())
	if err := b.Confirmations.Confirm(); err != nil {
		b.logf("confirm deploy: %v", err)
		return result{toast: b.text(msgFailureDeployState), alert: true}
	}
	b.deploy.stop()
	outcome := b.show(ctx, cb, screen{
		text:   b.text(msgDeployConfirmed, esc(pending.Revision)),
		markup: keyboard(backRow(b.L)),
	})
	outcome.toast = b.text(msgDeployConfirmedToast)
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
		b.logf("rollback deploy: %v", err)
		return result{toast: b.text(msgFailureDeployState), alert: true}
	}
	b.deploy.stop()
	outcome := b.show(ctx, cb, screen{
		text:   b.text(msgDeployRolledBack, esc(state.Revision)),
		markup: keyboard(backRow(b.L)),
	})
	outcome.toast = b.text(msgDeployRolledBackToast)
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
		b.text(msgDeployCountdownResumed)+"\n\n"+view.text, view.markup)
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
				text := b.text(msgDeployCountdownConfirmed, esc(revision))
				if state, err := b.Revisions.Load(watchCtx); err == nil && state.Revision != revision {
					text = b.text(msgDeployCountdownRolledBack, esc(revision), esc(state.Revision))
				}
				if err := b.API.EditMessageText(watchCtx, chatID, messageID, text, keyboard(backRow(b.L))); err != nil {
					b.logf("countdown edit: %v", err)
				}
				return
			}
		}
	})
}
