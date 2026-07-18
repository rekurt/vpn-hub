package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

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
	privateKey, _, err := domain.GenerateX25519KeyPair()
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
    profiles:
      - id: macbook-direct
        egress: direct
        address: "10.80.0.2/32"
        client_private_key: %q
tunnels: []
`, serverPublicKey, privateKey)

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

// `profile render` must be a real subcommand rather than a literal swallowed by
// Cobra's default ArbitraryArgs.
func TestProfileRenderIsASubcommand(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t)
	output := filepath.Join(t.TempDir(), "macbook.conf")
	if _, err := run(t, "profile", "render", "--config", configPath,
		"--device", "macbook", "--egress", "direct", "--output", output); err != nil {
		t.Fatalf("profile render failed: %v", err)
	}
	rendered, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read rendered profile: %v", err)
	}
	if !strings.Contains(string(rendered), "[Interface]") {
		t.Fatalf("rendered profile looks wrong: %q", rendered)
	}
}

func TestProfileRejectsUnknownPositionalArgument(t *testing.T) {
	t.Parallel()
	if _, err := run(t, "profile", "bogus", "--config", writeConfig(t)); err == nil {
		t.Fatal("expected unknown subcommand to be rejected")
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
