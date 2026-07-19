package bot

import "sync"

// opsGate serializes every mutation the bot performs: config edits, deploys,
// revocations, subscription refreshes.
//
// The hub's own locking does not cover this. The YAML editor is read-modify-write
// with no lock, and the canary namespace is a fixed singleton -- two concurrent
// refreshes collide destructively. One admin cannot tap two buttons at once, but a
// scheduled refresh can fire while a deploy runs, and the gate is what makes that
// safe. Contention answers immediately with what is running rather than queueing:
// a mutation decided minutes ago against a config that has changed since should be
// re-decided, not replayed.
type opsGate struct {
	busy    sync.Mutex
	stateMu sync.Mutex
	current string
}

// Acquire claims the gate for a named operation. When the gate is taken it returns
// the running operation's name so the refusal can say what to wait for.
func (g *opsGate) Acquire(name string) (release func(), busyWith string, ok bool) {
	if !g.busy.TryLock() {
		g.stateMu.Lock()
		defer g.stateMu.Unlock()
		return nil, g.current, false
	}
	g.stateMu.Lock()
	g.current = name
	g.stateMu.Unlock()
	return func() {
		g.stateMu.Lock()
		g.current = ""
		g.stateMu.Unlock()
		g.busy.Unlock()
	}, "", true
}
