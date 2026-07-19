package linux

import (
	"context"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func socksSpec() domain.EgressSpec {
	spec := egressSpec()
	spec.SocksPort = 11080
	return spec
}

// The proxy listens inside the namespace, so it inherits the isolation that matters:
// whatever it connects to leaves through that tunnel and no other.
func TestSocksRunsInsideTheNamespace(t *testing.T) {
	t.Parallel()
	host := &fakeHost{failures: map[string]error{
		"systemctl is-active --quiet vpn-hub-socks-corp.service": errNotRunning,
	}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.ensureSocks(context.Background(), socksSpec()); err != nil {
		t.Fatalf("ensureSocks: %v", err)
	}
	if !host.ran("ip netns exec vpn-hub-corp microsocks -i 10.90.0.2 -p 11080") {
		t.Fatalf("the proxy was not started inside the namespace; commands: %v", host.commands)
	}
}

// Restarting it on every reconcile would drop every connection through it once a
// minute.
func TestSocksIsLeftAloneWhenAlreadyRunning(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.ensureSocks(context.Background(), socksSpec()); err != nil {
		t.Fatalf("ensureSocks: %v", err)
	}
	if host.ran("systemd-run") {
		t.Fatalf("a running proxy should be left alone; commands: %v", host.commands)
	}
}

func TestNoSocksWithoutAPort(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	spec := socksSpec()
	spec.SocksPort = 0

	if err := (Egress{Run: host.run, SecretsDir: t.TempDir()}).ensureSocks(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if len(host.commands) != 0 {
		t.Fatalf("nothing should have run: %v", host.commands)
	}
}

// A client cannot reach inside a namespace, so the hub's end of the link has to
// answer on the same port.
func TestSocksIsReachableFromTheHubSideOfTheLink(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.forwardSocks(context.Background(), socksSpec()); err != nil {
		t.Fatalf("forwardSocks: %v", err)
	}
	var ruleset string
	for _, command := range host.commands {
		if strings.HasPrefix(command, "nft-main ") {
			ruleset = command
		}
	}
	if !strings.Contains(ruleset, "ip daddr 10.90.0.1 tcp dport 11080 dnat ip to 10.90.0.2:11080") {
		t.Fatalf("the hub side does not forward to the proxy:\n%s", ruleset)
	}
	// Its own table, so removing one tunnel's endpoint cannot disturb another's.
	if !strings.Contains(ruleset, "table inet vpn_hub_socks_corp") {
		t.Errorf("the endpoint should own its table:\n%s", ruleset)
	}
}
