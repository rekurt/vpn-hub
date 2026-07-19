package application

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

const wantedRevision = "abc123"

// converged describes a host that matches its revision exactly.
func converged(t *testing.T) (domain.IngressSpec, domain.ObservedState) {
	t.Helper()
	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, peerKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	spec := domain.IngressSpec{
		Interface:  "awg0",
		Address:    "10.80.0.1/24",
		ListenPort: 51820,
		PrivateKey: privateKey,
		Peers:      []domain.PeerSpec{{PublicKey: peerKey, AllowedIPs: []string{"10.80.0.2/32"}}},
	}
	observed := domain.ObservedState{
		FirewallRevision: wantedRevision,
		Ingress: domain.IngressObservation{
			Exists:     true,
			PublicKey:  publicKey,
			ListenPort: 51820,
			Peers: []domain.PeerObservation{
				{PublicKey: peerKey, AllowedIPs: []string{"10.80.0.2/32"}},
			},
		},
	}
	return spec, observed
}

func TestConvergedHostReportsNothing(t *testing.T) {
	t.Parallel()
	spec, observed := converged(t)
	if operations := Diff(spec, wantedRevision, observed); len(operations) != 0 {
		t.Fatalf("a converged host must produce no operations, got %v", operations)
	}
}

func TestDiff(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate   func(*domain.IngressSpec, *domain.ObservedState)
		resource string
		kind     domain.OperationKind
		reason   string
	}{
		"the ruleset was flushed": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) { o.FirewallRevision = "" },
			"nftables", domain.OpCreate, "absent",
		},
		"the ruleset is from another revision": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) { o.FirewallRevision = "stale" },
			"nftables", domain.OpUpdate, "revision stale",
		},
		"the interface is gone": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) { o.Ingress.Exists = false },
			"ingress", domain.OpCreate, "does not exist",
		},
		"the interface listens elsewhere": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) { o.Ingress.ListenPort = 500 },
			"ingress", domain.OpUpdate, "listens on 500",
		},
		"the interface carries another key": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) { o.Ingress.PublicKey = "someone-elses-key" },
			"ingress", domain.OpUpdate, "different key",
		},
		"a peer is missing": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) { o.Ingress.Peers = nil },
			"peer", domain.OpCreate, "does not carry it",
		},
		"a peer claims the wrong addresses": {
			func(_ *domain.IngressSpec, o *domain.ObservedState) {
				o.Ingress.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
			},
			"peer", domain.OpUpdate, "allowed addresses",
		},
		"a revoked peer is still present": {
			func(s *domain.IngressSpec, _ *domain.ObservedState) { s.Peers = nil },
			"peer", domain.OpDelete, "no longer names",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			spec, observed := converged(t)
			test.mutate(&spec, &observed)

			operations := Diff(spec, wantedRevision, observed)
			var found *domain.Operation
			for index := range operations {
				if operations[index].Resource.Type == test.resource {
					found = &operations[index]
					break
				}
			}
			if found == nil {
				t.Fatalf("expected an operation on %s, got %v", test.resource, operations)
			}
			if found.Kind != test.kind {
				t.Errorf("kind = %q, want %q", found.Kind, test.kind)
			}
			if !strings.Contains(found.Reason, test.reason) {
				t.Errorf("reason = %q, want it to mention %q", found.Reason, test.reason)
			}
		})
	}
}

// A reason that does not say what differs is no better than a bare "changed".
func TestEveryOperationExplainsItself(t *testing.T) {
	t.Parallel()
	spec, _ := converged(t)
	// Nothing on the host at all: no table, no interface, no peers.
	operations := Diff(spec, wantedRevision, domain.ObservedState{})
	if len(operations) == 0 {
		t.Fatal("an empty host must produce operations")
	}
	for _, operation := range operations {
		if operation.Reason == "" {
			t.Errorf("%s has no reason", operation.Resource.Type)
		}
		if operation.Resource.ID == "" {
			t.Errorf("%s has no resource ID", operation.Resource.Type)
		}
	}
}

// Peer identifiers reach the journal, and a full key there is more than is needed to
// tell peers apart.
func TestPeerOperationsDoNotPrintWholeKeys(t *testing.T) {
	t.Parallel()
	spec, observed := converged(t)
	fullKey := spec.Peers[0].PublicKey
	observed.Ingress.Peers = nil

	for _, operation := range Diff(spec, wantedRevision, observed) {
		if strings.Contains(operation.Resource.ID, fullKey) {
			t.Fatalf("the whole peer key reached the operation: %s", operation.Resource.ID)
		}
	}
}

// Ordering has to be stable or the journal shows spurious changes between ticks.
func TestDiffIsDeterministic(t *testing.T) {
	t.Parallel()
	spec, observed := converged(t)
	observed.Ingress.Peers = nil
	for range 5 {
		spec.Peers = append(spec.Peers, domain.PeerSpec{
			PublicKey:  strings.Repeat("A", 42) + string(rune('a'+len(spec.Peers))) + "=",
			AllowedIPs: []string{"10.80.0.9/32"},
		})
	}

	first := Diff(spec, wantedRevision, observed)
	for range 5 {
		if got := Diff(spec, wantedRevision, observed); !sameOperations(first, got) {
			t.Fatal("Diff returned a different order for the same input")
		}
	}
}

func sameOperations(a, b []domain.Operation) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
