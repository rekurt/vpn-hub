package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

func testCanary(host *fakeHost, dir string) Canary {
	return Canary{
		Egress:  Egress{Run: host.run, SecretsDir: dir},
		Run:     host.run,
		Timeout: 5 * time.Second,
	}
}

func canaryCandidate() domain.ProxyTunnel {
	return domain.ProxyTunnel{
		Protocol: "vless",
		Server:   "203.0.113.7",
		Port:     443,
		UUID:     "0f7c04a8-8f5d-4b3e-9d3d-4a1f0e0c9b21",
	}
}

const canaryProbeCommand = "ip netns exec vpn-hub-canary curl -sS --max-time 5 -o /dev/null https://1.1.1.1/cdn-cgi/trace"

// The canary's firewall hole hooks into forward and postrouting outside the
// reconciled table, so nothing else ever removes it: every path through a try must.
func TestTryLeavesNoFirewallStateBehind(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		failures map[string]error
		wantErr  bool
	}{
		"proven candidate": {failures: nil, wantErr: false},
		"failed probe": {
			failures: map[string]error{canaryProbeCommand: fmt.Errorf("exit status 28")},
			wantErr:  true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			host := &fakeHost{failures: tc.failures}
			canary := testCanary(host, dir)

			err := canary.Try(context.Background(), canaryCandidate(), "eth0")
			if tc.wantErr && err == nil {
				t.Fatal("expected the probe failure to surface")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("try: %v", err)
			}
			if !host.ran("nft delete table inet vpn_hub_canary") {
				t.Error("the canary firewall table was not deleted")
			}
			if _, err := os.Stat(filepath.Join(dir, "canary.nft")); !os.IsNotExist(err) {
				t.Errorf("canary.nft was left behind (stat: %v)", err)
			}
		})
	}
}

// The firewall hole is the one leftover nothing else ever clears: the agent
// replaces its own table and no other. So it has to be removed even when the
// teardown around it is out of time -- a namespace deletion that hangs used to
// eat the shared budget and leave the hole open with the context cancelled.
func TestTheFirewallHoleIsClosedEvenWhenTheTeardownRunsOut(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host := &fakeHost{}
	canary := testCanary(host, dir)

	// Already cancelled when the teardown begins, which is the worst case: every
	// step has to work from a budget of its own.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = canary.Try(ctx, canaryCandidate(), "eth0")

	if !host.ran("nft delete table inet vpn_hub_canary") {
		t.Fatalf("the firewall hole was left open; commands:\n%s", strings.Join(host.commands, "\n"))
	}
	if _, err := os.Stat(filepath.Join(dir, "canary.nft")); !os.IsNotExist(err) {
		t.Errorf("canary.nft was left behind (stat: %v)", err)
	}

	// And ahead of the steps that can block, not after them: a namespace deletion
	// that hangs must not be able to consume the time the removal needs.
	// `netns del` only ever happens in the teardown -- the setup adds -- so it
	// marks where the blocking part begins without matching the commands the
	// bring-up issues along the way.
	removal, teardown := -1, -1
	for index, command := range host.commands {
		if removal < 0 && strings.Contains(command, "nft delete table inet vpn_hub_canary") {
			removal = index
		}
		if teardown < 0 && strings.Contains(command, "netns del") {
			teardown = index
		}
	}
	if teardown >= 0 && removal > teardown {
		t.Errorf("the firewall removal waits on the teardown; commands:\n%s",
			strings.Join(host.commands, "\n"))
	}
}

// A candidate that failed does not make the hole it left less open, and that is
// the case where the leak hides best: "did not carry traffic" is an ordinary,
// expected answer, so an operator reading it has no reason to look further.
func TestAFailedTeardownSurvivesAFailedCandidate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host := &fakeHost{failures: map[string]error{
		canaryProbeCommand:                     fmt.Errorf("exit status 28"),
		"nft delete table inet vpn_hub_canary": fmt.Errorf("netlink: Connection timed out"),
	}}
	canary := testCanary(host, dir)

	err := canary.Try(context.Background(), canaryCandidate(), "eth0")
	if err == nil {
		t.Fatal("both failures went unreported")
	}
	if !strings.Contains(err.Error(), "did not carry traffic") {
		t.Errorf("the candidate's own failure was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "canary firewall table") {
		t.Errorf("the firewall table was left behind and nothing said so: %v", err)
	}
}

func TestSelectCandidateStopsAtTheFirstProven(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var commands []string
	curls := 0
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		commands = append(commands, line)
		if strings.Contains(line, "curl") {
			curls++
			if curls == 1 {
				return "", fmt.Errorf("exit status 28")
			}
		}
		return "", nil
	}
	canary := Canary{Egress: Egress{Run: run, SecretsDir: dir}, Run: run, Timeout: 5 * time.Second}

	first := canaryCandidate()
	second := canaryCandidate()
	second.Server = "198.51.100.9"

	var calls []string
	progress := func(tried, total int, rejected []string) {
		calls = append(calls, fmt.Sprintf("%d/%d rejected=%d", tried, total, len(rejected)))
	}

	chosen, reasons, err := canary.SelectCandidate(context.Background(),
		[]domain.ProxyTunnel{first, second}, "eth0", progress)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if chosen.Server != second.Server {
		t.Fatalf("chose %q, want %q", chosen.Server, second.Server)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "203.0.113.7:443") {
		t.Fatalf("rejections = %v", reasons)
	}
	if want := []string{"1/2 rejected=0", "2/2 rejected=1"}; !slices.Equal(calls, want) {
		t.Fatalf("progress calls = %v, want %v", calls, want)
	}
	if curls != 2 {
		t.Fatalf("probed %d times, want 2", curls)
	}
}

func TestAllowCanaryOutRendersTheRuleset(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	host := &fakeHost{}
	canary := testCanary(host, dir)
	spec := domain.EgressSpec{HostVeth: "vh-canary", ClientCIDR: "10.91.0.0/30"}

	if err := canary.allowCanaryOut(context.Background(), spec, "eth0"); err != nil {
		t.Fatalf("allowCanaryOut: %v", err)
	}

	path := filepath.Join(dir, "canary.nft")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("canary.nft mode = %o, want 0600", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, fragment := range []string{
		`iifname "vh-canary" oifname "eth0" accept`,
		`ip saddr 10.91.0.0/30 oifname "eth0" masquerade`,
	} {
		if !strings.Contains(string(content), fragment) {
			t.Errorf("ruleset is missing %q:\n%s", fragment, content)
		}
	}
	if !host.ran("nft -f " + path) {
		t.Error("the ruleset was not loaded with nft -f")
	}
}
