package bot

import (
	"strings"
	"testing"

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
