package bot

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

type notificationTrace struct {
	events    map[string]event
	countdown screen
}

func TestNotificationEventsAreLocalizedWithoutBehaviorDrift(t *testing.T) {
	t.Parallel()

	english := traceNotifications(t, LocaleEnglish)
	russian := traceNotifications(t, LocaleRussian)
	wantCategories := map[string]string{
		"agent-error":            "agent-error",
		"agent-recovered":        "converge",
		"auto-rollback":          "rollback",
		"drift":                  "drift",
		"drift-recovered":        "drift",
		"health-down":            "health",
		"health-up":              "health",
		"oob-pending":            "oob",
		"oob-protection-cleared": "oob",
		"oob-revision":           "oob",
		"oob-revocations":        "oob",
		"subscription-failure":   "subscription",
		"subscription-success":   "subscription",
	}

	if len(english.events) != len(wantCategories) || len(russian.events) != len(wantCategories) {
		t.Fatalf("event count: English=%d Russian=%d want=%d", len(english.events), len(russian.events), len(wantCategories))
	}
	seenCategories := map[string]bool{}
	for name, wantCategory := range wantCategories {
		en, enOK := english.events[name]
		ru, ruOK := russian.events[name]
		if !enOK || !ruOK {
			t.Fatalf("event %q missing: English=%v Russian=%v", name, enOK, ruOK)
		}
		if en.category != wantCategory || ru.category != wantCategory {
			t.Errorf("%s category: English=%q Russian=%q want=%q", name, en.category, ru.category, wantCategory)
		}
		seenCategories[en.category] = true
		if en.text == ru.text {
			t.Errorf("%s text did not change with locale: %q", name, en.text)
		}
		if got, want := screenCallbackData(en.markup), screenCallbackData(ru.markup); !reflect.DeepEqual(got, want) {
			t.Errorf("%s callbacks changed with locale: English=%v Russian=%v", name, got, want)
		}
		if en.debounce != ru.debounce {
			t.Errorf("%s debounce changed with locale: English=%s Russian=%s", name, en.debounce, ru.debounce)
		}
		if en.markup != nil && screenButtonText(en.markup) == screenButtonText(ru.markup) {
			t.Errorf("%s button labels did not change with locale: %q", name, screenButtonText(en.markup))
		}
	}
	for _, category := range notificationCategories {
		if !seenCategories[category.Key] {
			t.Errorf("notification category %q has no locale-matrix event", category.Key)
		}
	}

	if got, want := screenCallbackData(english.events["agent-error"].markup), []string{"log:u:" + agentUnit, "host:ra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("agent-error emergency callbacks = %v, want %v", got, want)
	}
	if got, want := english.events["agent-error"].debounce, 15*time.Minute; got != want {
		t.Errorf("agent-error debounce = %s, want %s", got, want)
	}
	if got, want := screenCallbackData(english.events["drift"].markup), []string{"log:u:" + agentUnit, "host:ra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("drift emergency callbacks = %v, want %v", got, want)
	}
	if got, want := screenCallbackData(english.events["oob-pending"].markup), []string{"dep:ok", "dep:rb!"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pending-deploy callbacks = %v, want %v", got, want)
	}
	if got, want := screenCallbackData(english.countdown.markup), []string{"dep:ok", "dep:rb!"}; !reflect.DeepEqual(got, want) {
		t.Errorf("countdown callbacks = %v, want %v", got, want)
	}
	if got, want := screenCallbackData(russian.countdown.markup), screenCallbackData(english.countdown.markup); !reflect.DeepEqual(got, want) {
		t.Errorf("countdown callbacks changed with locale: English=%v Russian=%v", want, got)
	}
	if english.countdown.text == russian.countdown.text {
		t.Errorf("countdown text did not change with locale: %q", english.countdown.text)
	}
	assertLocalizedNotificationFragments(t, english, russian)
}

func assertLocalizedNotificationFragments(t *testing.T, english, russian notificationTrace) {
	t.Helper()
	fragments := []struct {
		name    string
		english string
		russian string
	}{
		{"agent-error", "Agent:", "Агент:"},
		{"agent-recovered", "Agent:", "Агент:"},
		{"auto-rollback", "Automatic rollback", "Автооткат"},
		{"health-down", "Tunnel", "Туннель"},
		{"health-up", "healthy again", "снова здоров"},
		{"drift", "<b>Drift</b>", "<b>Дрейф</b>"},
		{"drift-recovered", "Drift resolved", "Дрейф устранён"},
		{"oob-pending", "deployed outside the bot", "Мимо бота задеплоена"},
		{"oob-protection-cleared", "protection was cleared outside the bot", "Страховка снята мимо бота"},
		{"oob-revision", "Revision changed outside the bot", "Ревизия изменилась мимо бота"},
		{"oob-revocations", "revoked-device list changed", "Список отозванных устройств изменился"},
		{"subscription-failure", "Scheduled refresh", "Плановое обновление"},
		{"subscription-success", "Scheduled refresh", "Плановое обновление"},
	}
	for _, item := range fragments {
		en := english.events[item.name].text
		ru := russian.events[item.name].text
		if !strings.Contains(en, item.english) || strings.Contains(en, item.russian) {
			t.Errorf("%s English framing is missing or mixed: %q", item.name, en)
		}
		if !strings.Contains(ru, item.russian) || strings.Contains(ru, item.english) {
			t.Errorf("%s Russian framing is missing or mixed: %q", item.name, ru)
		}
	}
	if !strings.Contains(english.events["drift"].text, "2 discrepancies") ||
		!strings.Contains(russian.events["drift"].text, "2 расхождения") {
		t.Errorf("drift plural is not localized: English=%q Russian=%q",
			english.events["drift"].text, russian.events["drift"].text)
	}
	if !strings.Contains(english.countdown.text, "2m 5s") || !strings.Contains(russian.countdown.text, "2м 5с") {
		t.Errorf("countdown units are not localized: English=%q Russian=%q", english.countdown.text, russian.countdown.text)
	}
}

func TestNotificationTextEscapesRuntimeValuesAndKeepsRawDetails(t *testing.T) {
	t.Parallel()
	l, err := NewLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}

	agent, ok := journalNotification(l, "probe vpn-hub-agent.service failed: <timeout & refused>")
	if !ok || !strings.Contains(agent.text, "probe vpn-hub-agent.service failed: &lt;timeout &amp; refused&gt;") {
		t.Fatalf("agent detail was not preserved and escaped: %q", agent.text)
	}
	health := healthNotification(l, "wg<nl>", "probe <timeout & refused>", false)
	if !strings.Contains(health.text, "wg&lt;nl&gt;") || !strings.Contains(health.text, "probe &lt;timeout &amp; refused&gt;") {
		t.Fatalf("health runtime values were not preserved and escaped: %q", health.text)
	}
	oob := outOfBandNotifications(l,
		observedState{revision: "old<rev>"},
		observedState{revision: "new&rev"},
	)
	if len(oob) != 1 || !strings.Contains(oob[0].text, "old&lt;rev&gt;") || !strings.Contains(oob[0].text, "new&amp;rev") {
		t.Fatalf("revision values were not preserved and escaped: %+v", oob)
	}
}

func traceNotifications(t *testing.T, locale Locale) notificationTrace {
	t.Helper()
	l, err := NewLocalizer(locale)
	if err != nil {
		t.Fatal(err)
	}
	trace := notificationTrace{events: map[string]event{}}
	journal := []struct {
		name string
		line string
	}{
		{"auto-rollback", "revision oldbeef was not confirmed within the deadline; restored goodcafe"},
		{"agent-recovered", "converged on revision deadbeef"},
		{"agent-error", "probe vpn-hub-agent.service failed: timeout"},
	}
	for _, item := range journal {
		ev, ok := journalNotification(l, item.line)
		if !ok {
			t.Fatalf("journal line %q was ignored", item.line)
		}
		trace.events[item.name] = ev
	}

	before := observedState{revision: "oldbeef", pending: "oldbeef", revoked: "phone"}
	oobCases := []struct {
		name  string
		after observedState
	}{
		{"oob-pending", observedState{revision: "oldbeef", pending: "newcafe", revoked: "phone"}},
		{"oob-protection-cleared", observedState{revision: "oldbeef", revoked: "phone"}},
		{"oob-revision", observedState{revision: "newcafe", pending: "oldbeef", revoked: "phone"}},
		{"oob-revocations", observedState{revision: "oldbeef", pending: "oldbeef", revoked: "laptop"}},
	}
	for _, item := range oobCases {
		events := outOfBandNotifications(l, before, item.after)
		if len(events) != 1 {
			t.Fatalf("%s emitted %d events, want 1: %+v", item.name, len(events), events)
		}
		trace.events[item.name] = events[0]
	}

	trace.events["health-down"] = healthNotification(l, "wg-nl", "HTTPS probe timed out", false)
	trace.events["health-up"] = healthNotification(l, "wg-nl", "HTTPS probe succeeded", true)
	operations := []domain.Operation{
		{Kind: domain.OpUpdate, Resource: domain.ResourceRef{Type: "peer", ID: "macbook"}, Reason: "key differs"},
		{Kind: domain.OpDelete, Resource: domain.ResourceRef{Type: "ingress", ID: "awg0"}, Reason: "stale"},
	}
	trace.events["drift"] = driftNotification(l, operations)
	trace.events["drift-recovered"] = driftRecoveredNotification(l)

	instance, _ := hubFixtureLocale(t, locale)
	tunnel := domain.Tunnel{ID: "sub-nl", Source: domain.TunnelSource{Kind: domain.SourceSubscription}}
	instance.Refresh = func(context.Context, domain.Tunnel, func(int, int, []string)) (domain.ProxyTunnel, []string, error) {
		return domain.ProxyTunnel{Server: "203.0.113.7", Port: 443}, []string{"candidate probe timed out"}, nil
	}
	instance.refreshScheduled(context.Background(), tunnel)
	trace.events["subscription-success"] = <-instance.events
	instance.Refresh = func(context.Context, domain.Tunnel, func(int, int, []string)) (domain.ProxyTunnel, []string, error) {
		return domain.ProxyTunnel{}, []string{"candidate probe timed out"}, fmt.Errorf("provider returned <503>")
	}
	instance.refreshScheduled(context.Background(), tunnel)
	trace.events["subscription-failure"] = <-instance.events

	trace.countdown = scr(renderCountdown(l, "deadbeef", 2*time.Minute+5*time.Second))
	return trace
}

func TestClassifyAgentLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line     string
		category string
		ok       bool
	}{
		{"converged on revision 6b419dc34476ad09", "converge", true},
		{"revision aaaa was not confirmed within the deadline; restored bbbb", "rollback", true},
		{"create nftables/vpn_hub: fingerprint differs", "", false},
		{"update ingress/awg0: peer set differs", "", false},
		{"delete peer/laptop: no longer deployed", "", false},
		{"read desired state: open /var/lib/vpn-hub/desired-state.json: no such file", "agent-error", true},
		{"", "", false},
		{"   ", "", false},
	}
	for _, testCase := range cases {
		l, err := NewLocalizer(LocaleEnglish)
		if err != nil {
			t.Fatal(err)
		}
		category, text, ok := classifyAgentLine(l, testCase.line)
		if ok != testCase.ok || category != testCase.category {
			t.Errorf("%q: got (%q, %v), want (%q, %v)", testCase.line, category, ok, testCase.category, testCase.ok)
		}
		if ok && !strings.Contains(text, "Agent") && category != "rollback" {
			t.Errorf("%q: text does not name the agent: %q", testCase.line, text)
		}
	}
}

// One bad probe is a blip; two in a row is an alert; recovery is only announced
// after an alert went out.
func TestHealthBoardHysteresis(t *testing.T) {
	t.Parallel()
	board := &healthBoard{}
	bad := healthEntry{ID: "wg-nl", Status: domain.HealthUnhealthy}
	good := healthEntry{ID: "wg-nl", Status: domain.HealthHealthy}

	if down, up := board.observe(bad); down || up {
		t.Fatal("a single failure must not alert")
	}
	if down, _ := board.observe(bad); !down {
		t.Fatal("the second consecutive failure must alert")
	}
	if down, _ := board.observe(bad); down {
		t.Fatal("an ongoing failure must not alert again")
	}
	if _, up := board.observe(good); !up {
		t.Fatal("recovery after an alert must be announced")
	}
	if _, up := board.observe(good); up {
		t.Fatal("staying healthy is not news")
	}

	// Healthy without a preceding alert stays silent too.
	if down, up := board.observe(healthEntry{ID: "corp-a", Status: domain.HealthHealthy}); down || up {
		t.Fatal("healthy out of nowhere must not alert")
	}
	// Unknown neither alerts nor resets an alert.
	board.observe(bad)
	board.observe(bad) // alerted again
	if down, up := board.observe(healthEntry{ID: "wg-nl", Status: domain.HealthUnknown}); down || up {
		t.Fatal("unknown must stay silent")
	}
	if _, up := board.observe(good); !up {
		t.Fatal("recovery after unknown must still be announced")
	}
}

func TestHealthBoardPrune(t *testing.T) {
	t.Parallel()
	board := &healthBoard{}
	board.observe(healthEntry{ID: "gone", Status: domain.HealthHealthy})
	board.observe(healthEntry{ID: "kept", Status: domain.HealthHealthy})
	board.prune(map[string]bool{"kept": true})
	if board.get("gone") != nil {
		t.Fatal("a removed tunnel survived the prune")
	}
	if board.get("kept") == nil {
		t.Fatal("a present tunnel was pruned")
	}
}

// The notifier's delivery decision is where a refactor most easily drops or
// duplicates an alert; pin every branch.
func TestShouldDeliver(t *testing.T) {
	t.Parallel()
	instance, _ := hubFixture(t)
	st := newNotifierState()
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	// An auto-rollback is delivered, and it suppresses an out-of-band notice that
	// follows within two minutes (the rollback is what rewrote the state files).
	if !instance.shouldDeliver(st, event{category: "rollback", text: "rb"}, base) {
		t.Fatal("rollback must be delivered")
	}
	if instance.shouldDeliver(st, event{category: "oob", text: "changed"}, base.Add(30*time.Second)) {
		t.Fatal("oob within 2 min of a rollback must be suppressed")
	}
	if !instance.shouldDeliver(st, event{category: "oob", text: "changed"}, base.Add(3*time.Minute)) {
		t.Fatal("oob well after a rollback must be delivered")
	}

	// Debounce collapses repeats of the same text within the window, but a
	// different text passes.
	err := event{category: "agent-error", text: "boom", debounce: 15 * time.Minute}
	if !instance.shouldDeliver(st, err, base) {
		t.Fatal("first agent error must be delivered")
	}
	if instance.shouldDeliver(st, err, base.Add(time.Minute)) {
		t.Fatal("a repeat within the debounce window must be suppressed")
	}
	if !instance.shouldDeliver(st, event{category: "agent-error", text: "other", debounce: 15 * time.Minute}, base.Add(time.Minute)) {
		t.Fatal("a different error text must be delivered")
	}
	if !instance.shouldDeliver(st, err, base.Add(20*time.Minute)) {
		t.Fatal("the same error after the window must be delivered again")
	}

	// A muted category is never delivered.
	instance.alerts.set("drift", false)
	if instance.shouldDeliver(st, event{category: "drift", text: "d"}, base) {
		t.Fatal("a muted category must not be delivered")
	}
}

func TestAlertSwitches(t *testing.T) {
	t.Parallel()
	switches := newAlertSwitches()
	if !switches.get("health") {
		t.Fatal("categories default to on")
	}
	if switches.toggle("health") {
		t.Fatal("toggle must turn it off")
	}
	if switches.get("health") {
		t.Fatal("the toggle did not stick")
	}
	// Unknown categories default to on, so a new category is never born muted.
	if !switches.get("brand-new") {
		t.Fatal("unknown categories must default to on")
	}
}

// The debounce key carries the event's text, and an agent-error's text is a line
// from the journal -- so without a sweep every distinct failure the agent ever
// reported stayed in the map, in a process that runs for months between deploys.
func TestDebounceForgetsWhatCanNoLongerSuppress(t *testing.T) {
	t.Parallel()
	instance := &Bot{alerts: newAlertSwitches()}
	st := newNotifierState()
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	const window = 15 * time.Minute

	// A hundred failures, each with its own text, an hour apart: four windows
	// between them, so none can suppress any other.
	for index := range 100 {
		text := fmt.Sprintf("reconcile failed: tunnel-%d", index)
		if !instance.shouldDeliver(st, event{category: "agent-error", text: text, debounce: window},
			base.Add(time.Duration(index)*time.Hour)) {
			t.Fatalf("event %d was suppressed by an unrelated one", index)
		}
	}
	if len(st.lastSent) != 1 {
		t.Errorf("the debounce map kept %d entries, want only the most recent", len(st.lastSent))
	}

	// And the suppression it exists for still works: the same text inside the
	// window is held back, outside it is not.
	repeat := event{category: "agent-error", text: "the same failure", debounce: window}
	if !instance.shouldDeliver(st, repeat, base) {
		t.Fatal("the first occurrence was suppressed")
	}
	if instance.shouldDeliver(st, repeat, base.Add(window-time.Second)) {
		t.Error("a repeat inside the window was delivered")
	}
	if !instance.shouldDeliver(st, repeat, base.Add(window+time.Second)) {
		t.Error("a repeat past the window was suppressed")
	}
}
