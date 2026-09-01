//go:build integration && linux

// Constrained to linux, unlike its neighbours: it sets SO_MARK directly, and that
// constant does not exist on other platforms -- so a plain `go vet -tags=integration`
// on a maintainer's Mac would fail to build rather than skip.

package linux_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"vpn-hub/internal/adapters/linux"
	"vpn-hub/internal/domain"
)

// TestMarkedTrafficCannotReachTheHubsOwnServices reproduces the way in that the
// listener's own configuration cannot close.
//
// A device on the fallback path reaches the hub by its endpoint, which is a
// public address: refusing private destinations leaves it untouched. The local
// table resolves the hub's own address over loopback -- priority 0, ahead of
// every fwmark rule -- so the connection arrives at the input chain by `lo`, and
// the ordinary `iif lo accept` would hand it to SSH without the cloud firewall,
// which decides who may reach SSH, ever seeing it.
//
// What separates such a connection from the hub's own traffic is the socket mark
// every listener connection carries. This drives that distinction with real
// sockets against a real ruleset, because it rests on the mark surviving the trip
// through loopback -- which nothing in a rendered string can show.
func TestMarkedTrafficCannotReachTheHubsOwnServices(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loads a ruleset and needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}

	// A public address on the host, standing in for the hub's endpoint: private
	// ones are already refused by the listener, so they would prove nothing.
	const hubAddress = "203.0.113.5"
	try("ip addr add %s/32 dev lo", hubAddress)
	t.Cleanup(func() { try("ip addr del %s/32 dev lo", hubAddress) })

	service, err := net.Listen("tcp", hubAddress+":2222")
	if err != nil {
		t.Fatalf("stand in for a service on the hub: %v", err)
	}
	defer func() { _ = service.Close() }()
	go func() {
		for {
			connection, err := service.Accept()
			if err != nil {
				return
			}
			_, _ = connection.Write([]byte("SSH-2.0-hub\n"))
			_ = connection.Close()
		}
	}()

	plan := domain.FirewallPlan{
		IngressInterface: "awg0", UplinkInterface: "lo",
		ClientCIDR: "10.80.0.0/24", DNSAddress: "10.80.0.1",
		ListenPort: 51820, ManagementPort: 22,
		Egresses: []domain.EgressGroup{{
			ID: domain.EgressDirect, Mark: 0x100, Interface: "lo",
		}},
	}
	t.Cleanup(func() { try("nft delete table inet vpn_hub") })
	rulesPath := filepath.Join(t.TempDir(), "localguard.nft")
	if err := os.WriteFile(rulesPath, []byte(linux.RenderRuleset(plan)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nft", "-f", rulesPath).CombinedOutput(); err != nil {
		t.Fatalf("the ruleset did not load: %v\n%s", err, out)
	}

	// Marked, as every connection the listener opens is -- including for a device
	// on direct, which is marked precisely so it is recognisable here.
	if reached(t, hubAddress, 0x100) {
		t.Error("a device on the fallback path reached a service on the hub's own address")
	}
	// And the hub's own traffic, which carries no mark, is untouched: the drop has
	// to close a way in without closing the machine's own loopback.
	if !reached(t, hubAddress, 0) {
		t.Error("the hub can no longer reach its own services")
	}
}

// reached reports whether a connection carrying the given socket mark got an
// answer. Mark zero means an ordinary socket.
func reached(t *testing.T, address string, mark int) bool {
	t.Helper()
	dialer := net.Dialer{Timeout: 3 * time.Second}
	if mark != 0 {
		dialer.Control = func(_, _ string, connection syscall.RawConn) error {
			var setErr error
			if err := connection.Control(func(handle uintptr) {
				setErr = syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			}); err != nil {
				return err
			}
			return setErr
		}
	}
	connection, err := dialer.Dial("tcp", fmt.Sprintf("%s:2222", address))
	if err != nil {
		return false
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return false
	}
	buffer := make([]byte, 16)
	read, err := connection.Read(buffer)
	return err == nil && read > 0
}
