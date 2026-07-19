package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// annotated carries the kind of comment that makes a network configuration
// readable, plus formatting a naive re-encode would flatten.
const annotated = `# Corporate network, contact: netops@corp.example
tunnels:
  - id: corp-a
    type: wireguard
    role: private-network
    source: {kind: config, value: "corp-a.conf"}
    # Only the finance subnet is reachable; the rest is firewalled off anyway.
    routes:
      - "10.20.0.0/16"
    dns_zones:
      - corp.internal
`

func editable(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corp-a.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// The comment explaining why a route exists is often worth more than the route.
func TestEditingPreservesComments(t *testing.T) {
	t.Parallel()
	path := editable(t, annotated)

	if err := (Editor{Root: path}).SetTunnelField("corp-a", "enabled", "false"); err != nil {
		t.Fatalf("SetTunnelField: %v", err)
	}

	result := read(t, path)
	for _, comment := range []string{
		"# Corporate network, contact: netops@corp.example",
		"# Only the finance subnet is reachable",
	} {
		if !strings.Contains(result, comment) {
			t.Errorf("comment was lost: %s\n---\n%s", comment, result)
		}
	}
	if !strings.Contains(result, "enabled: false") {
		t.Errorf("the field was not set:\n%s", result)
	}
}

func TestSetTunnelFieldReplacesAnExistingValue(t *testing.T) {
	t.Parallel()
	path := editable(t, annotated)
	editor := Editor{Root: path}

	if err := editor.SetTunnelField("corp-a", "enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetTunnelField("corp-a", "enabled", "true"); err != nil {
		t.Fatal(err)
	}

	result := read(t, path)
	if strings.Count(result, "enabled:") != 1 {
		t.Fatalf("expected one enabled key, got:\n%s", result)
	}
	if !strings.Contains(result, "enabled: true") {
		t.Fatalf("value was not replaced:\n%s", result)
	}
}

func TestRoutesCanBeAddedAndRemoved(t *testing.T) {
	t.Parallel()
	path := editable(t, annotated)
	editor := Editor{Root: path}

	if err := editor.AppendListItem("corp-a", "routes", "10.30.0.0/16"); err != nil {
		t.Fatalf("AppendListItem: %v", err)
	}
	if !strings.Contains(read(t, path), "10.30.0.0/16") {
		t.Fatal("the route was not added")
	}

	if err := editor.RemoveListItem("corp-a", "routes", "10.20.0.0/16"); err != nil {
		t.Fatalf("RemoveListItem: %v", err)
	}
	result := read(t, path)
	if strings.Contains(result, "10.20.0.0/16") {
		t.Fatalf("the route was not removed:\n%s", result)
	}
	if !strings.Contains(result, "10.30.0.0/16") {
		t.Fatalf("the wrong route was removed:\n%s", result)
	}
}

// Adding a field that is not there yet has to work, since `enabled` is absent until
// someone disables something.
func TestAppendCreatesAMissingList(t *testing.T) {
	t.Parallel()
	path := editable(t, `tunnels:
  - id: corp-a
    type: wireguard
`)
	if err := (Editor{Root: path}).AppendListItem("corp-a", "dns_zones", "corp.internal"); err != nil {
		t.Fatalf("AppendListItem: %v", err)
	}
	if !strings.Contains(read(t, path), "corp.internal") {
		t.Fatal("the zone was not added")
	}
}

func TestEditorRejects(t *testing.T) {
	t.Parallel()
	path := editable(t, annotated)
	editor := Editor{Root: path}

	if err := editor.SetTunnelField("nowhere", "enabled", "false"); err == nil {
		t.Error("expected an unknown tunnel to be an error")
	}
	if err := editor.AppendListItem("corp-a", "routes", "10.20.0.0/16"); err == nil {
		t.Error("expected a duplicate route to be refused")
	}
	if err := editor.RemoveListItem("corp-a", "routes", "10.99.0.0/16"); err == nil {
		t.Error("expected removing an absent route to be an error")
	}
}

// In a directory layout only the tunnel's own file may change, which is the whole
// reason for splitting them up.
func TestOnlyTheTargetFileIsRewritten(t *testing.T) {
	t.Parallel()
	root := layout(t)
	before := read(t, filepath.Join(root, "tunnels", "provider-nl.yaml"))

	if err := (Editor{Root: root}).SetTunnelField("corp-a", "enabled", "false"); err != nil {
		t.Fatalf("SetTunnelField: %v", err)
	}

	if after := read(t, filepath.Join(root, "tunnels", "provider-nl.yaml")); after != before {
		t.Fatalf("an unrelated file was rewritten:\n%s", after)
	}
	if !strings.Contains(read(t, filepath.Join(root, "tunnels", "corp-a.yaml")), "enabled: false") {
		t.Fatal("the target file was not changed")
	}
}

func TestDeviceEgressCanBeChanged(t *testing.T) {
	t.Parallel()
	root := layout(t)

	if err := (Editor{Root: root}).SetDeviceField("laptop", "egress", "corp-a"); err != nil {
		t.Fatalf("SetDeviceField: %v", err)
	}
	if !strings.Contains(read(t, filepath.Join(root, "devices.yaml")), "egress: corp-a") {
		t.Fatal("the device egress was not changed")
	}
}
