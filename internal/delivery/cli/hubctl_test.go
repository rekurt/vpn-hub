package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type cliEndpointResolverStub map[string][]netip.Addr

func (r cliEndpointResolverStub) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	return r[host], nil
}

// run executes hubctl with args against a throwaway config and returns combined output.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	command := NewHubctlCommand(&out, &out)
	command.SetArgs(args)
	err := command.ExecuteContext(context.Background())
	return out.String(), err
}

// writeConfig renders a minimal valid hub configuration into a temp dir.
func writeConfig(t *testing.T) string {
	t.Helper()
	_, devicePublicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	_, serverPublicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate server key pair: %v", err)
	}

	body := fmt.Sprintf(`hub:
  endpoint: "vpn.example.test:51820"
  server_public_key: %q
  client_cidr: "10.80.0.0/24"
  dns_address: "10.80.0.1"
devices:
  - id: macbook
    address: "10.80.0.2/32"
    public_key: %q
    egress: direct
tunnels: []
`, serverPublicKey, devicePublicKey)

	path := filepath.Join(t.TempDir(), "hub.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestValidateAcceptsMinimalConfig(t *testing.T) {
	t.Parallel()
	output, err := run(t, "validate", "--config", writeConfig(t))
	if err != nil {
		t.Fatalf("validate failed: %v (output %q)", err, output)
	}
	if !strings.Contains(output, "valid: revision=") {
		t.Fatalf("unexpected output %q", output)
	}
}

// The README documents `hubctl test tunnel <id>`. Before the command was split into a
// real subcommand, ExactArgs(1) on a command named "test" rejected that exact invocation.
func TestTunnelSubcommandAcceptsDocumentedInvocation(t *testing.T) {
	t.Parallel()
	output, err := run(t, "test", "tunnel", "missing", "--config", writeConfig(t))
	if err == nil {
		t.Fatalf("expected a lookup failure, got output %q", output)
	}
	if strings.Contains(err.Error(), "accepts 1 arg") {
		t.Fatalf("argument parsing rejected the documented form: %v", err)
	}
	if !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("expected a tunnel lookup error, got %v", err)
	}
}

// `device add` generates the key pair and writes the client profile, which is the
// only moment a private key exists.
func TestDeviceAddWritesAProfile(t *testing.T) {
	t.Parallel()
	output := filepath.Join(t.TempDir(), "laptop.conf")
	printed, err := run(t, "device", "add", "laptop", "--config", writeConfig(t),
		"--egress", "direct", "--address", "10.80.0.9/32", "--output", output)
	if err != nil {
		t.Fatalf("device add failed: %v (output %q)", err, printed)
	}
	if !strings.Contains(printed, "public_key:") || !strings.Contains(printed, "egress: direct") {
		t.Fatalf("expected an entry to paste into devices, got %q", printed)
	}

	rendered, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read rendered profile: %v", err)
	}
	if !strings.Contains(string(rendered), "[Interface]") {
		t.Fatalf("rendered profile looks wrong: %q", rendered)
	}
	// The hub keeps only public halves, so the private key must not be echoed into
	// anything but the profile itself.
	if strings.Contains(printed, "PrivateKey") {
		t.Error("the private key was printed alongside the entry")
	}
}

// A zero interval used to reach time.NewTicker and panic.
func TestServeRejectsNonPositiveInterval(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	command := NewAgentCommand(&out, &out)
	command.SetArgs([]string{"serve", "--interval", "0"})
	err := command.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected serve to reject a zero interval")
	}
	if !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// `deploy` used to default to a rehearsal, so the documented invocation reported a
// revision that compiled and wrote nothing at all. Worse for a remote hub:
// `--confirm-within` armed no timer either, so the operator believed a bad revision
// would roll itself back when nothing had been deployed to roll back from.
func TestDeployWritesTheRevision(t *testing.T) {
	t.Parallel()
	config := writeConfig(t)
	stateDir := t.TempDir()

	output, err := run(t, "--config", config, "deploy", "--state-dir", stateDir)
	if err != nil {
		t.Fatalf("deploy: %v (%s)", err, output)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "desired-state.json")); err != nil {
		t.Fatalf("deploy wrote no revision: %v; output: %s", err, output)
	}
}

// unrevoke undoes revoke, so a mistaken revocation is fixable over SSH without
// hand-editing the state file.
func TestDeviceUnrevokeLiftsARevocation(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()

	if output, err := run(t, "device", "revoke", "laptop", "--state-dir", stateDir); err != nil {
		t.Fatalf("revoke: %v (%s)", err, output)
	}
	output, err := run(t, "device", "unrevoke", "laptop", "--state-dir", stateDir)
	if err != nil {
		t.Fatalf("unrevoke: %v (%s)", err, output)
	}
	if !strings.Contains(output, "lifted the revocation") {
		t.Fatalf("unexpected output %q", output)
	}
}

// subscription restore is the SSH-side counterpart to the bot's LKG button.
func TestSubscriptionRestoreReturnsLastKnownGood(t *testing.T) {
	t.Parallel()
	configDir := t.TempDir()
	links := filepath.Join(configDir, "subscriptions")
	if err := os.MkdirAll(links, 0o700); err != nil {
		t.Fatal(err)
	}
	// The active link is broken; the last-known-good one still works.
	if err := os.WriteFile(filepath.Join(links, "xray.link"), []byte("vless://u@2.2.2.2:443?type=tcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(links, "xray.link.last-known-good"), []byte("vless://u@1.1.1.1:443?type=tcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := run(t, "subscription", "restore", "xray", "--config-dir", configDir)
	if err != nil {
		t.Fatalf("restore: %v (%s)", err, output)
	}
	if !strings.Contains(output, "restored 1.1.1.1:443") {
		t.Fatalf("expected the last-known-good upstream, got %q", output)
	}
}

func TestDeployWithConfirmationArmsTheRollback(t *testing.T) {
	t.Parallel()
	config := writeConfig(t)
	stateDir := t.TempDir()

	// The first deploy has nothing to roll back to, so the rollback only becomes
	// meaningful from the second onwards.
	if output, err := run(t, "--config", config, "deploy", "--state-dir", stateDir); err != nil {
		t.Fatalf("first deploy: %v (%s)", err, output)
	}
	output, err := run(t, "--config", config, "deploy", "--state-dir", stateDir, "--confirm-within", "5m")
	if err != nil {
		t.Fatalf("deploy: %v (%s)", err, output)
	}
	// The proof that the timer exists is that confirming it succeeds.
	if output, err := run(t, "confirm", "--state-dir", stateDir); err != nil {
		t.Fatalf("nothing was awaiting confirmation: %v (%s)", err, output)
	}
}

// A revoked device must not reach the revision the agent converges on. The exclusion
// itself is well tested as a pure function; that `deploy` calls it was not, and
// removing the call left the suite green.
func TestDeployExcludesRevokedDevices(t *testing.T) {
	t.Parallel()
	config := writeConfig(t)
	stateDir := t.TempDir()

	if output, err := run(t, "--config", config, "device", "revoke", "macbook", "--state-dir", stateDir); err != nil {
		t.Fatalf("revoke: %v (%s)", err, output)
	}
	if output, err := run(t, "--config", config, "deploy", "--state-dir", stateDir); err != nil {
		t.Fatalf("deploy: %v (%s)", err, output)
	}

	revision, err := os.ReadFile(filepath.Join(stateDir, "desired-state.json"))
	if err != nil {
		t.Fatalf("read revision: %v", err)
	}
	if strings.Contains(string(revision), "macbook") {
		t.Fatalf("the revoked device is still in the revision:\n%s", revision)
	}
}

// The first deploy cannot arm a rollback, and must not claim to. An operator who
// reads the usual line trusts a safety net that is not there -- on exactly the hub
// where a bad revision cuts the session it would be repaired from.
func TestTheFirstDeploySaysNoRollbackWasArmed(t *testing.T) {
	t.Parallel()
	config := writeConfig(t)

	output, err := run(t, "--config", config, "deploy", "--state-dir", t.TempDir(), "--confirm-within", "5m")
	if err != nil {
		t.Fatalf("deploy: %v (%s)", err, output)
	}
	if !strings.Contains(output, "no rollback was armed") {
		t.Errorf("the output promises a rollback that was not armed:\n%s", output)
	}
}

func TestProvePublicCandidatesPinsBeforeCanaryAndReturnsPinnedChoice(t *testing.T) {
	t.Parallel()
	resolver := cliEndpointResolverStub{
		"edge.provider.example": {netip.MustParseAddr("9.9.9.9")},
	}
	candidate := domain.ProxyTunnel{
		Server:    "edge.provider.example",
		TLS:       domain.ProxyTLS{Enabled: true},
		Transport: domain.ProxyTransport{Type: "ws"},
	}

	chosen, _, err := provePublicCandidates(context.Background(), resolver, []domain.ProxyTunnel{candidate},
		func(_ context.Context, candidates []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			return candidates[0], nil, nil
		})
	if err != nil {
		t.Fatalf("provePublicCandidates: %v", err)
	}
	if chosen.Server != "9.9.9.9" || chosen.OriginServer != "edge.provider.example" {
		t.Fatalf("chosen = %+v, want pinned candidate", chosen)
	}
	if chosen.TLS.ServerName != "edge.provider.example" || chosen.Transport.Host != "edge.provider.example" {
		t.Fatalf("handshake hosts were not preserved: %+v", chosen)
	}
}

func TestProvePublicCandidatesRejectsPrivateBeforeCanary(t *testing.T) {
	t.Parallel()
	called := false
	_, _, err := provePublicCandidates(context.Background(), cliEndpointResolverStub{},
		[]domain.ProxyTunnel{{Server: "10.0.0.8"}},
		func(_ context.Context, _ []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			called = true
			return domain.ProxyTunnel{}, nil, nil
		})
	if err == nil || !strings.Contains(err.Error(), "not a public endpoint") {
		t.Fatalf("provePublicCandidates error = %v", err)
	}
	if called {
		t.Fatal("private candidate reached the canary")
	}
}
