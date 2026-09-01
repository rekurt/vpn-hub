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

func TestAddDeviceAppendsToTheExistingList(t *testing.T) {
	t.Parallel()
	root := layout(t)

	err := (Editor{Root: root}).AddDevice("phone", "10.80.0.3/32", "k4pv4YKUzz1E3d8087I9Sc4vVW02EZ7Pj1Nt4pIJXm0=", "direct")
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	result := read(t, filepath.Join(root, "devices.yaml"))
	for _, expected := range []string{"id: laptop", "id: phone", "address: 10.80.0.3/32", "egress: direct"} {
		if !strings.Contains(result, expected) {
			t.Errorf("missing %q in:\n%s", expected, result)
		}
	}
}

func TestAddDeviceRefusesADuplicate(t *testing.T) {
	t.Parallel()
	root := layout(t)

	err := (Editor{Root: root}).AddDevice("laptop", "10.80.0.9/32", "k4pv4YKUzz1E3d8087I9Sc4vVW02EZ7Pj1Nt4pIJXm0=", "direct")
	if err == nil {
		t.Fatal("expected a duplicate device to be refused")
	}
	if strings.Contains(read(t, filepath.Join(root, "devices.yaml")), "10.80.0.9/32") {
		t.Fatal("the duplicate was written anyway")
	}
}

// A single-file configuration with no devices yet gains the list, not a parse error.
func TestAddDeviceCreatesAMissingList(t *testing.T) {
	t.Parallel()
	path := editable(t, "# The hub, nothing else yet.\nhub:\n  endpoint: \"vpn.example.test:51820\"\n")

	err := (Editor{Root: path}).AddDevice("phone", "10.80.0.3/32", "k4pv4YKUzz1E3d8087I9Sc4vVW02EZ7Pj1Nt4pIJXm0=", "direct")
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	result := read(t, path)
	if !strings.Contains(result, "# The hub, nothing else yet.") {
		t.Errorf("comment was lost:\n%s", result)
	}
	for _, expected := range []string{"devices:", "id: phone"} {
		if !strings.Contains(result, expected) {
			t.Errorf("missing %q in:\n%s", expected, result)
		}
	}
	if count := strings.Count(result, "devices:"); count != 1 {
		t.Errorf("expected one devices key, got %d:\n%s", count, result)
	}
}

// `devices: []` is what a file looks like after every device left; the list has to
// come back in block style rather than one long flow line.
func TestAddDeviceRevivesAnEmptyList(t *testing.T) {
	t.Parallel()
	path := editable(t, "devices: []\n")

	err := (Editor{Root: path}).AddDevice("phone", "10.80.0.3/32", "k4pv4YKUzz1E3d8087I9Sc4vVW02EZ7Pj1Nt4pIJXm0=", "direct")
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	result := read(t, path)
	if !strings.Contains(result, "id: phone") {
		t.Fatalf("the device was not added:\n%s", result)
	}
	if count := strings.Count(result, "devices:"); count != 1 {
		t.Errorf("expected one devices key, got %d:\n%s", count, result)
	}
}

func TestRemoveDeviceIsAddDevicesRevert(t *testing.T) {
	t.Parallel()
	root := layout(t)
	before := read(t, filepath.Join(root, "devices.yaml"))

	editor := Editor{Root: root}
	if err := editor.AddDevice("phone", "10.80.0.3/32", "k4pv4YKUzz1E3d8087I9Sc4vVW02EZ7Pj1Nt4pIJXm0=", "direct"); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := editor.RemoveDevice("phone"); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}

	result := read(t, filepath.Join(root, "devices.yaml"))
	if strings.Contains(result, "phone") {
		t.Fatalf("the device was not removed:\n%s", result)
	}
	if !strings.Contains(result, "id: laptop") {
		t.Fatalf("the wrong device was removed:\n%s", before)
	}

	if err := editor.RemoveDevice("phone"); err == nil {
		t.Error("expected removing an absent device to be an error")
	}
}

func TestSetHubFieldEditsHubYAML(t *testing.T) {
	t.Parallel()
	root := layout(t)

	if err := (Editor{Root: root}).SetHubField("endpoint", "new.example.test:51821"); err != nil {
		t.Fatalf("SetHubField: %v", err)
	}
	if !strings.Contains(read(t, filepath.Join(root, "hub.yaml")), "new.example.test:51821") {
		t.Fatal("the endpoint was not changed")
	}
}

func TestSetHubFieldSingleFile(t *testing.T) {
	t.Parallel()
	path := editable(t, "# Why this endpoint: closest region.\nhub:\n  endpoint: \"old:51820\"\n  dns_address: \"10.80.0.1\"\n")

	if err := (Editor{Root: path}).SetHubField("dns_address", "10.80.0.53"); err != nil {
		t.Fatalf("SetHubField: %v", err)
	}
	result := read(t, path)
	if !strings.Contains(result, "10.80.0.53") || !strings.Contains(result, "old:51820") {
		t.Fatalf("wrong edit:\n%s", result)
	}
	if !strings.Contains(result, "# Why this endpoint") {
		t.Fatalf("comment was lost:\n%s", result)
	}
}

func TestHubMapFieldLifecycle(t *testing.T) {
	t.Parallel()
	path := editable(t, "hub:\n  endpoint: \"old:51820\"\n")
	editor := Editor{Root: path}

	// The nested map does not exist yet and has to be created.
	if err := editor.SetHubMapField("awg_interface", "jc", "5"); err != nil {
		t.Fatalf("SetHubMapField: %v", err)
	}
	if err := editor.SetHubMapField("awg_interface", "jc", "7"); err != nil {
		t.Fatalf("SetHubMapField update: %v", err)
	}
	result := read(t, path)
	if !strings.Contains(result, "awg_interface") || !strings.Contains(result, "jc: \"7\"") && !strings.Contains(result, "jc: 7") {
		t.Fatalf("the parameter was not set:\n%s", result)
	}
	if strings.Count(result, "jc:") != 1 {
		t.Fatalf("duplicate key:\n%s", result)
	}

	if err := editor.RemoveHubMapField("awg_interface", "jc"); err != nil {
		t.Fatalf("RemoveHubMapField: %v", err)
	}
	if strings.Contains(read(t, path), "jc:") {
		t.Fatal("the parameter was not removed")
	}
	if err := editor.RemoveHubMapField("awg_interface", "jc"); err == nil {
		t.Fatal("removing an absent key must be an error")
	}
}

func TestTunnelMapFieldLifecycle(t *testing.T) {
	t.Parallel()
	root := layout(t)
	editor := Editor{Root: root}

	if err := editor.SetTunnelMapField("provider-nl", "health", "https_url", "https://1.1.1.1/cdn-cgi/trace"); err != nil {
		t.Fatalf("SetTunnelMapField: %v", err)
	}
	result := read(t, filepath.Join(root, "tunnels", "provider-nl.yaml"))
	if !strings.Contains(result, "health:") || !strings.Contains(result, "https_url:") {
		t.Fatalf("the probe was not set:\n%s", result)
	}

	if err := editor.RemoveTunnelMapField("provider-nl", "health", "https_url"); err != nil {
		t.Fatalf("RemoveTunnelMapField: %v", err)
	}
	if strings.Contains(read(t, filepath.Join(root, "tunnels", "provider-nl.yaml")), "https_url:") {
		t.Fatal("the probe was not removed")
	}
	if err := editor.RemoveTunnelMapField("provider-nl", "health", "https_url"); err == nil {
		t.Fatal("removing an absent probe must be an error")
	}
	if err := editor.SetTunnelMapField("nowhere", "health", "dns_name", "x.test"); err == nil {
		t.Fatal("an unknown tunnel must be an error")
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

func TestClientACLCanBeAddedAndRemoved(t *testing.T) {
	t.Parallel()
	path := editable(t, annotated)
	editor := Editor{Root: path}
	if err := editor.AddClientACL("any", "laptop", "tcp", 22); err != nil {
		t.Fatalf("AddClientACL: %v", err)
	}
	result := read(t, path)
	for _, expected := range []string{"client_acls:", "source: any", "target: laptop", "protocol: tcp", "port: 22"} {
		if !strings.Contains(result, expected) {
			t.Fatalf("missing %q in:\n%s", expected, result)
		}
	}
	if err := editor.RemoveClientACL("any", "laptop", "tcp", 22); err != nil {
		t.Fatalf("RemoveClientACL: %v", err)
	}
	if strings.Contains(read(t, path), "target: laptop") {
		t.Fatalf("ACL was not removed:\n%s", read(t, path))
	}
}
