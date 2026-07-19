package linux

import (
	"context"
	"strings"
	"testing"
)

func TestStatusParsesShowOutput(t *testing.T) {
	t.Parallel()
	systemctl := Systemctl{Run: func(_ context.Context, name string, args ...string) (string, error) {
		// The unit name must be a positional argument, after "--".
		if name != "systemctl" || args[0] != "show" || args[len(args)-2] != "--" || args[len(args)-1] != "vpn-hub-agent.service" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return "ActiveState=active\nSubState=running\nExecMainStartTimestamp=Fri 2026-07-17 10:00:00 UTC\nNRestarts=2\n", nil
	}}

	status, err := systemctl.Status(context.Background(), "vpn-hub-agent.service")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	// A unit name that could be read as a flag is refused before exec.
	if _, err := systemctl.Status(context.Background(), "--foo"); err == nil {
		t.Fatal("expected a suspicious unit name to be rejected")
	}
	if status.Active != "active" || status.Sub != "running" || status.Restarts != 2 {
		t.Fatalf("unexpected status %+v", status)
	}
	if status.Since != "Fri 2026-07-17 10:00:00 UTC" {
		t.Fatalf("unexpected start time %q", status.Since)
	}
}

func TestListMatchingParsesUnits(t *testing.T) {
	t.Parallel()
	systemctl := Systemctl{Run: func(_ context.Context, _ string, args ...string) (string, error) {
		if args[len(args)-1] != "vpn-hub-*" {
			t.Fatalf("pattern was not passed: %v", args)
		}
		return "vpn-hub-agent.service loaded active running Reconcile desired state\n" +
			"vpn-hub-proxy-nl.service loaded active running sing-box for nl\n" +
			"vpn-hub-openvpn-de.service loaded failed failed OpenVPN for de\n", nil
	}}

	units, err := systemctl.ListMatching(context.Background(), "vpn-hub-*")
	if err != nil {
		t.Fatalf("ListMatching: %v", err)
	}
	if len(units) != 3 {
		t.Fatalf("expected 3 units, got %+v", units)
	}
	if units[2].Unit != "vpn-hub-openvpn-de.service" || units[2].Active != "failed" {
		t.Fatalf("unexpected unit %+v", units[2])
	}
}

func TestQREncoderFeedsStdin(t *testing.T) {
	t.Parallel()
	var seen string
	encoder := QREncoder{Exec: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		seen = name + " " + strings.Join(args, " ") + " <<< " + stdin
		return []byte{0x89, 'P', 'N', 'G'}, nil
	}}

	image, err := encoder.PNG(context.Background(), "[Interface]\nPrivateKey = secret\n")
	if err != nil {
		t.Fatalf("PNG: %v", err)
	}
	if len(image) != 4 {
		t.Fatalf("unexpected image %v", image)
	}
	// The profile goes through stdin so the private key never reaches argv.
	if !strings.HasPrefix(seen, "qrencode -t PNG -o - <<< [Interface]") {
		t.Fatalf("unexpected invocation %q", seen)
	}
}
