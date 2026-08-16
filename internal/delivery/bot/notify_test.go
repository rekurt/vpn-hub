package bot

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

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
		category, text, ok := classifyAgentLine(testCase.line)
		if ok != testCase.ok || category != testCase.category {
			t.Errorf("%q: got (%q, %v), want (%q, %v)", testCase.line, category, ok, testCase.category, testCase.ok)
		}
		if ok && !strings.Contains(text, "Агент") && category != "rollback" {
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
