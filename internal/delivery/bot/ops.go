package bot

import (
	"context"
	"sync"
)

// busyResult is the standard answer to a tap that arrives while a mutation is
// running: name what holds the gate so the admin knows what to wait for.
func busyResult(l Localizer, busyWith string) result {
	return result{toast: l.Text(msgBusyToast, busyWith), alert: true}
}

// opsGate serializes every mutation the bot performs: config edits, deploys,
// revocations, subscription refreshes.
//
// The per-file locks in the editor and the canary make each individual write safe
// against a concurrent hubctl, but the bot's operations are multi-step -- a deploy
// compiles then arms then saves; an edit writes then validates then maybe reverts --
// and nothing but this gate keeps two of them from interleaving. One admin cannot
// tap two buttons at once, but a scheduled refresh can fire while a deploy runs.
// Contention answers immediately with what is running rather than queueing: a
// mutation decided against a config that has changed since should be re-decided,
// not replayed.
type opsGate struct {
	mu      sync.Mutex
	busy    bool
	current string
}

// claim takes the gate for a named operation, or hands back the refusal to answer
// with. release is nil exactly when the gate was busy, which is what makes
// forgetting the check a nil dereference at the first tap rather than two
// mutations interleaving in production.
//
// The caller still writes `defer release()` itself: a helper that ran the body in
// a closure would hold the gate for exactly the same span while re-indenting
// every handler in the package, which buys nothing the deferred call does not.
func (b *Bot) claim(name string) (release func(), busy *result) {
	release, busyWith, ok := b.gate.Acquire(name)
	if !ok {
		refusal := busyResult(b.L, busyWith)
		return nil, &refusal
	}
	return release, nil
}

// claimForDialog is claim for the handlers a typed message drives rather than a
// tap: they answer with a message of their own, so there is no result to return.
// release is nil when the gate was busy, and the refusal has already been sent.
func (b *Bot) claimForDialog(ctx context.Context, name string) (release func()) {
	release, busyWith, ok := b.gate.Acquire(name)
	if !ok {
		b.send(ctx, b.text(msgBusyDialog, esc(busyWith)), nil)
		return nil
	}
	return release
}

// Acquire claims the gate for a named operation. When the gate is taken it returns
// the running operation's name so the refusal can say what to wait for. Check and
// claim happen under one lock, so a refused caller always learns what is actually
// running rather than a name from a torn read.
func (g *opsGate) Acquire(name string) (release func(), busyWith string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy {
		return nil, g.current, false
	}
	g.busy = true
	g.current = name
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.busy = false
		g.current = ""
	}, "", true
}
