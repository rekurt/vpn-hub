package bot

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

const (
	msgNotifyAgentRollback      MessageID = "notification/agent_rollback"
	msgNotifyAgentConverged     MessageID = "notification/agent_converged"
	msgNotifyAgentError         MessageID = "notification/agent_error"
	msgNotifyButtonJournal      MessageID = "notification/button/journal"
	msgNotifyButtonAgentJournal MessageID = "notification/button/agent_journal"
	msgNotifyOOBPending         MessageID = "notification/oob/pending"
	msgNotifyOOBProtectionClear MessageID = "notification/oob/protection_cleared"
	msgNotifyOOBRevision        MessageID = "notification/oob/revision"
	msgNotifyOOBRevocations     MessageID = "notification/oob/revocations"
	msgNotifyHealthDown         MessageID = "notification/health/down"
	msgNotifyHealthUp           MessageID = "notification/health/up"
	msgNotifyDriftRecovered     MessageID = "notification/drift/recovered"
	msgNotifyDriftHeader        MessageID = "notification/drift/header"
	msgNotifyDriftOperation     MessageID = "notification/drift/operation"
	msgNotifyDriftMore          MessageID = "notification/drift/more"
	msgNotifyDriftAdvice        MessageID = "notification/drift/advice"
)

// event is one thing the bot decided to say on its own.
type event struct {
	category string
	text     string
	markup   *tg.InlineKeyboardMarkup
	// debounce suppresses repeats of the same text within the window; an agent
	// failing every tick must not become a message every tick.
	debounce time.Duration
}

func (b *Bot) emit(ev event) {
	select {
	case b.events <- ev:
	default:
		// Dropping is deliberate: if the queue is full the chat is unreachable or
		// flooded, and blocking a watcher on it would stop the watching.
		b.logf("notification dropped: %s", ev.category)
	}
}

// notifierState is what the notifier remembers between events; kept separate so the
// delivery decision is a pure function that a test can drive without goroutines.
type notifierState struct {
	lastSent     map[string]time.Time
	lastRollback time.Time
	// longestDebounce is the widest window any event has asked for, which is how
	// far back lastSent has to remember. See forget.
	longestDebounce time.Duration
}

func newNotifierState() *notifierState {
	return &notifierState{lastSent: map[string]time.Time{}}
}

// forget drops the entries that can no longer suppress anything.
//
// The debounce key carries the event's text, and an agent-error's text is a line
// from the journal -- so every distinct failure the agent ever reports adds a key
// that was never removed. The bot runs for months between deploys, which made this
// a map that only grew.
//
// Nothing is lost: an entry older than the longest window any event has asked for
// would compare as "long enough ago" for every event that could match it, so
// dropping it and finding nothing are the same answer. The sweep is O(entries) and
// happens once per window rather than per event.
func (st *notifierState) forget(now time.Time) {
	if st.longestDebounce == 0 {
		return
	}
	for key, sent := range st.lastSent {
		if now.Sub(sent) >= st.longestDebounce {
			delete(st.lastSent, key)
		}
	}
}

// shouldDeliver decides whether one event reaches the admin: category toggle,
// auto-rollback suppression, and per-text debounce. It updates the state, so it is
// called once per event in arrival order.
func (b *Bot) shouldDeliver(st *notifierState, ev event, now time.Time) bool {
	if ev.category == "rollback" {
		st.lastRollback = now
	}
	if !b.alerts.get(ev.category) {
		return false
	}
	// An auto-rollback rewrites the state files; reporting that again as "changed
	// outside the bot" would be the same news twice.
	if ev.category == "oob" && now.Sub(st.lastRollback) < 2*time.Minute {
		return false
	}
	if ev.debounce > 0 {
		key := ev.category + "|" + ev.text
		if last, ok := st.lastSent[key]; ok && now.Sub(last) < ev.debounce {
			return false
		}
		if ev.debounce > st.longestDebounce {
			st.longestDebounce = ev.debounce
		}
		// Swept on the way in rather than on a timer of its own: this map is only
		// ever touched from the notifier goroutine, and a ticker would be a second
		// writer to guard for a map that grows a few entries an hour at worst.
		st.forget(now)
		st.lastSent[key] = now
	}
	return true
}

// notifier is the single mouth for every watcher: category toggles, debounce and
// suppression live in shouldDeliver so the watchers stay simple.
func (b *Bot) notifier(ctx context.Context) {
	st := newNotifierState()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-b.events:
			if b.shouldDeliver(st, ev, b.Now()) {
				b.send(ctx, ev.text, ev.markup)
			}
		}
	}
}

// --- alert switches --------------------------------------------------------

type alertSwitches struct {
	mu      sync.Mutex
	enabled map[string]bool
}

func newAlertSwitches() *alertSwitches {
	enabled := map[string]bool{}
	for _, category := range notificationCategories {
		enabled[category.Key] = true
	}
	return &alertSwitches{enabled: enabled}
}

func (s *alertSwitches) get(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, known := s.enabled[key]
	return !known || value
}

func (s *alertSwitches) toggle(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled[key] = !s.enabled[key]
	return s.enabled[key]
}

// set restores one saved switch; unknown keys are kept too, so a category renamed
// away simply stops mattering instead of breaking the load.
func (s *alertSwitches) set(key string, value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled[key] = value
}

func (s *alertSwitches) snapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make(map[string]bool, len(s.enabled))
	for key, value := range s.enabled {
		copied[key] = value
	}
	return copied
}

// --- health board ----------------------------------------------------------

// healthBoard caches the latest probe per tunnel and applies hysteresis: one bad
// probe is a blip, two in a row is an alert, and recovery is announced only after
// an alert went out.
type healthBoard struct {
	mu      sync.Mutex
	entries map[string]healthEntry
	fails   map[string]int
	alerted map[string]bool
}

func (h *healthBoard) init() {
	if h.entries == nil {
		h.entries = map[string]healthEntry{}
		h.fails = map[string]int{}
		h.alerted = map[string]bool{}
	}
}

// store records a probe without feeding the alert logic -- manual checks report
// their result in the chat already.
func (h *healthBoard) store(entry healthEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	h.entries[entry.ID] = entry
}

func (h *healthBoard) observe(entry healthEntry) (down, up bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	h.entries[entry.ID] = entry
	switch entry.Status {
	case "unhealthy":
		h.fails[entry.ID]++
		if h.fails[entry.ID] == 2 && !h.alerted[entry.ID] {
			h.alerted[entry.ID] = true
			return true, false
		}
	case "healthy":
		h.fails[entry.ID] = 0
		if h.alerted[entry.ID] {
			h.alerted[entry.ID] = false
			return false, true
		}
	default:
		// Unknown is "could not measure", not "broken": it neither counts toward an
		// alert nor cancels one.
		h.fails[entry.ID] = 0
	}
	return false, false
}

func (h *healthBoard) get(id string) *healthEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	if entry, ok := h.entries[id]; ok {
		return &entry
	}
	return nil
}

func (h *healthBoard) list() []healthEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	entries := make([]healthEntry, 0, len(h.entries))
	for _, entry := range h.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

func (h *healthBoard) prune(known map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	for id := range h.entries {
		if !known[id] {
			delete(h.entries, id)
			delete(h.fails, id)
			delete(h.alerted, id)
		}
	}
}

// --- self marks ------------------------------------------------------------

// selfMarks lets the file watcher tell the bot's own writes from someone else's:
// the bot marks itself right before touching state, and the watcher stays quiet
// about changes that follow within the window.
type selfMarks struct {
	mu sync.Mutex
	at time.Time
}

func (s *selfMarks) mark(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.at = now
}

func (s *selfMarks) recent(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.at.IsZero() && now.Sub(s.at) < 15*time.Second
}

// --- journal watcher -------------------------------------------------------

// operationPattern matches the diff lines the agent prints when it converges a
// change; they are expected activity, not trouble.
var operationPattern = regexp.MustCompile(`^(create|update|delete) [a-z]+/`)

const agentConvergedRevisionPrefix = "converged on revision "

func classifyAgentLine(l Localizer, message string) (category, text string, ok bool) {
	message = strings.TrimSpace(message)
	switch {
	case message == "":
		return "", "", false
	case strings.Contains(message, "was not confirmed within the deadline; restored"):
		return "rollback", l.Text(msgNotifyAgentRollback, esc(message)), true
	case strings.HasPrefix(message, agentConvergedRevisionPrefix):
		revision := strings.TrimSpace(strings.TrimPrefix(message, agentConvergedRevisionPrefix))
		return "converge", l.Text(msgNotifyAgentConverged, esc(revision)), true
	case operationPattern.MatchString(message):
		return "", "", false
	default:
		return "agent-error", l.Text(msgNotifyAgentError, esc(message)), true
	}
}

func journalNotification(l Localizer, message string) (event, bool) {
	category, text, ok := classifyAgentLine(l, message)
	if !ok {
		return event{}, false
	}
	ev := event{category: category, text: text}
	switch category {
	case "agent-error":
		ev.debounce = 15 * time.Minute
		ev.markup = keyboard([]tg.InlineKeyboardButton{
			btn("📜 "+l.Text(msgNotifyButtonJournal), "log:u:"+agentUnit),
			btn("🔁 "+l.Text(msgButtonRestartAgent), "host:ra"),
		})
	case "rollback":
		ev.markup = notificationStatusMarkup(l)
	}
	return ev, true
}

func (b *Bot) watchJournal(ctx context.Context) {
	for entry := range b.Journal.Follow(ctx, []string{agentUnit}) {
		// systemd's own lifecycle lines ride along under -u; they belong to init,
		// not to the agent, and unit start/stop already shows on the host screen.
		if entry.Unit != agentUnit {
			continue
		}
		ev, ok := journalNotification(b.L, entry.Message)
		if !ok {
			continue
		}
		b.emit(ev)
	}
}

// --- state-file watcher ----------------------------------------------------

// watchStateFiles notices what happens to the shared state outside the bot:
// hubctl over SSH writes the same files, and silence about that would leave the
// admin believing the chat shows the whole story.
type observedState struct {
	revision string
	pending  string
	revoked  string
}

func notificationStatusMarkup(l Localizer) *tg.InlineKeyboardMarkup {
	return keyboard([]tg.InlineKeyboardButton{btn("📊 "+l.Text(MsgButtonStatus), "st")})
}

func outOfBandNotifications(l Localizer, previous, current observedState) []event {
	status := notificationStatusMarkup(l)
	events := make([]event, 0, 4)
	if current.pending != previous.pending && current.pending != "" {
		events = append(events, event{
			category: "oob",
			text:     l.Text(msgNotifyOOBPending, esc(current.pending)),
			markup: keyboard([]tg.InlineKeyboardButton{
				btn("✅ "+l.Text(msgButtonConfirm), "dep:ok"),
				btn("↩️ "+l.Text(msgButtonRollback), "dep:rb!"),
			}),
		})
	}
	if current.pending != previous.pending && current.pending == "" && current.revision == previous.revision {
		events = append(events, event{category: "oob", text: l.Text(msgNotifyOOBProtectionClear), markup: status})
	}
	if current.revision != previous.revision {
		events = append(events, event{
			category: "oob",
			text: l.Text(msgNotifyOOBRevision,
				esc(orDash(previous.revision)), esc(orDash(current.revision))),
			markup: status,
		})
	}
	if current.revoked != previous.revoked {
		events = append(events, event{category: "oob", text: l.Text(msgNotifyOOBRevocations), markup: status})
	}
	return events
}

func (b *Bot) watchStateFiles(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	primed := false
	var previous observedState
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		current := observedState{}
		if state, err := b.Revisions.Load(ctx); err == nil {
			current.revision = state.Revision
		}
		if p, armed, err := b.Confirmations.Load(); err == nil && armed {
			current.pending = p.Revision
		}
		if ids, err := b.Revocations.Load(ctx); err == nil {
			current.revoked = strings.Join(ids, ",")
		}

		if !primed {
			primed = true
			previous = current
			continue
		}
		if self := b.self.recent(b.Now()); !self {
			for _, ev := range outOfBandNotifications(b.L, previous, current) {
				b.emit(ev)
			}
		}
		previous = current
	}
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

// --- health prober ---------------------------------------------------------

func (b *Bot) probeHealth(ctx context.Context) {
	ticker := time.NewTicker(b.Cfg.Notifications.HealthInterval)
	defer ticker.Stop()
	for {
		b.probeAllTunnels(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (b *Bot) probeAllTunnels(ctx context.Context) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.logf("health probe: %v", err)
		return
	}
	known := map[string]bool{}
	for _, tunnel := range cfg.Tunnels {
		if !tunnel.IsEnabled() {
			continue
		}
		known[tunnel.ID] = true
		health, err := b.Service.TestTunnel(ctx, cfg, tunnel.ID)
		if err != nil {
			b.logf("health probe %s: %v", tunnel.ID, err)
			continue
		}
		entry := healthEntry{ID: tunnel.ID, Status: health.Status, Reason: health.Reason, CheckedAt: health.CheckedAt}
		down, up := b.health.observe(entry)
		if down {
			b.emit(healthNotification(b.L, tunnel.ID, health.Reason, false))
		}
		if up {
			b.emit(healthNotification(b.L, tunnel.ID, health.Reason, true))
		}
	}
	b.health.prune(known)
}

func healthNotification(l Localizer, tunnelID, reason string, recovered bool) event {
	id := msgNotifyHealthDown
	if recovered {
		id = msgNotifyHealthUp
	}
	return event{
		category: "health",
		text:     l.Text(id, esc(tunnelID), esc(reason)),
		markup: keyboard([]tg.InlineKeyboardButton{
			btn("🚇 "+l.Text(msgButtonToTunnel), "tun:c:"+tunnelID),
		}),
	}
}

// --- drift watcher ---------------------------------------------------------

// watchDrift compares the host with the revision on a slow clock. A single
// snapshot of drift can be the agent mid-tick, so only drift that survives two
// consecutive checks is worth a message.
func (b *Bot) watchDrift(ctx context.Context) {
	ticker := time.NewTicker(b.Cfg.Notifications.DriftInterval)
	defer ticker.Stop()
	sawDrift, alerted := false, false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		state, err := b.Revisions.Load(ctx)
		if err != nil {
			continue
		}
		operations, err := b.Reconciler.Plan(ctx, state)
		if err != nil {
			b.logf("drift check: %v", err)
			continue
		}
		switch {
		case len(operations) == 0:
			if alerted {
				b.emit(driftRecoveredNotification(b.L))
			}
			sawDrift, alerted = false, false
		case sawDrift && !alerted:
			b.emit(driftNotification(b.L, operations))
			alerted = true
		default:
			sawDrift = true
		}
	}
}

func driftNotification(l Localizer, operations []domain.Operation) event {
	var text strings.Builder
	text.WriteString(l.Text(msgNotifyDriftHeader, len(operations),
		plural(l, len(operations), msgPluralDiscrepancyOne, msgPluralDiscrepancyFew, msgPluralDiscrepancyMany)))
	for index, operation := range operations {
		if index == 10 {
			text.WriteString(l.Text(msgNotifyDriftMore, len(operations)-index))
			break
		}
		text.WriteString(l.Text(msgNotifyDriftOperation, esc(operation.String())))
	}
	text.WriteString(l.Text(msgNotifyDriftAdvice))
	return event{
		category: "drift",
		text:     text.String(),
		markup: keyboard([]tg.InlineKeyboardButton{
			btn("📜 "+l.Text(msgNotifyButtonAgentJournal), "log:u:"+agentUnit),
			btn("🔁 "+l.Text(msgButtonRestartAgent), "host:ra"),
		}),
	}
}

func driftRecoveredNotification(l Localizer) event {
	return event{category: "drift", text: l.Text(msgNotifyDriftRecovered)}
}
