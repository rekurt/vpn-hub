package linux

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

// fakeHost records the commands an adapter issues and replays canned output.
type fakeHost struct {
	commands []string
	replies  map[string]string
	failures map[string]error
}

func (f *fakeHost) run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, line)
	if err, failing := f.failures[line]; failing {
		return "", err
	}
	return f.replies[line], nil
}

func (f *fakeHost) ran(fragment string) bool {
	for _, command := range f.commands {
		if strings.Contains(command, fragment) {
			return true
		}
	}
	return false
}

func newIngress(t *testing.T, host *fakeHost) Ingress {
	t.Helper()
	return Ingress{Run: host.run, SecretsDir: t.TempDir()}
}

func spec() domain.IngressSpec {
	return domain.IngressSpec{
		Interface:  "awg0",
		Address:    "10.80.0.1/24",
		ListenPort: 51820,
		PrivateKey: "cOFA+ItsMPRFpKt4kPsUlqUlkxHnFvJdWuBK5rXqL0Y=",
		Parameters: map[string]string{"Jc": "4", "Jmin": "64"},
		Peers: []domain.PeerSpec{
			{PublicKey: "aYo1x9b951yd4mtMeKkW/vyOJvU08j2UU96u/Ve9QWA=", AllowedIPs: []string{"10.80.0.2/32"}},
		},
	}
}

func TestApplyCreatesTheInterfaceWhenAbsent(t *testing.T) {
	t.Parallel()
	// No reply for `awg show`, so the adapter sees an interface that is not there.
	host := &fakeHost{failures: map[string]error{
		"awg show awg0 dump": fmt.Errorf("no such device"),
	}}
	if err := newIngress(t, host).Apply(context.Background(), spec()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !host.ran("ip link add dev awg0 type amneziawg") {
		t.Error("the interface was not created")
	}
	if !host.ran("ip addr replace 10.80.0.1/24 dev awg0") {
		t.Error("the address was not assigned")
	}
	if !host.ran("ip link set awg0 up") {
		t.Error("the interface was not brought up")
	}
	if !host.ran("peer aYo1x9b951yd4mtMeKkW/vyOJvU08j2UU96u/Ve9QWA= allowed-ips 10.80.0.2/32") {
		t.Error("the peer was not configured")
	}
}

// Re-creating the interface on every reconcile would drop live client sessions.
func TestApplyDoesNotRecreateAnExistingInterface(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"awg show awg0 dump": realDump}}
	if err := newIngress(t, host).Apply(context.Background(), spec()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if host.ran("ip link add") {
		t.Error("an existing interface must not be recreated")
	}
}

// A revoked device has to lose its peer entry, or it keeps handshaking.
func TestApplyRemovesPeersThatAreNoLongerConfigured(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"awg show awg0 dump": realDump}}
	configuration := spec()
	configuration.Peers = nil

	if err := newIngress(t, host).Apply(context.Background(), configuration); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("peer aYo1x9b951yd4mtMeKkW/vyOJvU08j2UU96u/Ve9QWA= remove") {
		t.Errorf("the stale peer was not removed; commands: %v", host.commands)
	}
}

// argv is world-readable through /proc, so the key may only travel by file.
func TestPrivateKeyNeverAppearsInArguments(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"awg show awg0 dump": realDump}}
	configuration := spec()

	if err := newIngress(t, host).Apply(context.Background(), configuration); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, command := range host.commands {
		if strings.Contains(command, configuration.PrivateKey) {
			t.Fatalf("the private key leaked into a command line: %s", command)
		}
	}
	if !host.ran("private-key ") {
		t.Error("expected the key to be passed as a file path")
	}
}

func TestPrivateKeyFileIsNotReadableByOthers(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	host := &fakeHost{replies: map[string]string{"awg show awg0 dump": realDump}}
	ingress := Ingress{Run: host.run, SecretsDir: directory}

	if err := ingress.Apply(context.Background(), spec()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(directory + "/awg0.key")
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", info.Mode().Perm())
	}
}

// Obfuscation parameters must be ordered so a repeated reconcile issues an identical
// command and stays diffable.
func TestParametersAreOrderedAndLowercased(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"awg show awg0 dump": realDump}}
	if err := newIngress(t, host).Apply(context.Background(), spec()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("jc 4 jmin 64") {
		t.Errorf("expected sorted lower-case parameters; commands: %v", host.commands)
	}
}

func TestApplyRejectsAnIncompleteSpec(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	if err := newIngress(t, host).Apply(context.Background(), domain.IngressSpec{Interface: "awg0"}); err == nil {
		t.Fatal("expected an error for a spec with no address or key")
	}
}
