package linux

import (
	"context"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func egressSpec() domain.EgressSpec {
	return domain.EgressSpec{
		TunnelID: "corp", Namespace: "vpn-hub-corp",
		HostVeth: "vh-corp", PeerVeth: "uplink0",
		HostAddress: "10.90.0.1/30", PeerAddress: "10.90.0.2/30",
		Mark: 0x101, RouteTable: 100, ClientCIDR: "10.80.0.0/24",
		Interface: "wg0",
		Tunnel: domain.WireGuardTunnel{
			PrivateKey: "cOFA+ItsMPRFpKt4kPsUlqUlkxHnFvJdWuBK5rXqL0Y=",
			Addresses:  []string{"10.7.0.5/32"},
			Peer: domain.WireGuardPeer{
				PublicKey: "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=",
				Endpoint:  "provider.example:51820",
			},
		},
	}
}

// The agent keeps a private mount namespace, where a namespace bind mount would be
// confined and unusable. Delegating to a transient unit is what lets the sandbox stay
// on, so it is worth asserting rather than leaving to a comment.
func TestNamespaceCreationIsDelegatedToATransientUnit(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"ip -j netns list": "[]"}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	_ = egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()})

	if !host.ran("systemd-run --quiet --wait --collect --unit=vpn-hub-netns-add-vpn-hub-corp ip netns add") {
		t.Fatalf("namespace creation was not delegated; commands: %v", host.commands)
	}
	for _, command := range host.commands {
		if strings.HasPrefix(command, "ip netns add") {
			t.Fatalf("namespace created directly, which the sandbox would confine: %s", command)
		}
	}
}

// Integration tests and systemd-less hosts have no sandbox to escape.
func TestDirectNamespacesSkipsTheDelegation(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{"ip -j netns list": "[]"}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir(), DirectNamespaces: true}

	_ = egress.Apply(context.Background(), []domain.EgressSpec{egressSpec()})

	if !host.ran("ip netns add vpn-hub-corp") {
		t.Fatalf("expected a direct call; commands: %v", host.commands)
	}
	if host.ran("systemd-run") {
		t.Fatal("delegation should be skipped when it buys nothing")
	}
}

// A namespace the revision no longer names has to go, and its removal is a mount
// operation too.
func TestStaleNamespacesAreRemovedThroughTheSameRoute(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{
		"ip -j netns list": `[{"name":"vpn-hub-gone"},{"name":"unrelated"}]`,
	}}
	egress := Egress{Run: host.run, SecretsDir: t.TempDir()}

	if err := egress.Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !host.ran("--unit=vpn-hub-netns-del-vpn-hub-gone ip netns del") {
		t.Fatalf("the stale namespace was not removed; commands: %v", host.commands)
	}
	// Namespaces the hub did not create are none of its business.
	if host.ran("unrelated") {
		t.Fatal("a namespace outside the hub's prefix was touched")
	}
}
