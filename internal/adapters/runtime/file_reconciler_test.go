package runtime

import (
	"context"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

func TestRevocationStoreRoundTrip(t *testing.T) {
	t.Parallel()
	store := RevocationStore{StateDir: t.TempDir()}
	ctx := context.Background()

	ids, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("loading before anything is revoked must succeed: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no revocations, got %v", ids)
	}

	if err := store.Add(ctx, "phone"); err != nil {
		t.Fatal(err)
	}
	// Revoking twice must not duplicate the entry.
	if err := store.Add(ctx, "phone"); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(ctx, "macbook"); err != nil {
		t.Fatal(err)
	}

	ids, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "macbook" || ids[1] != "phone" {
		t.Fatalf("revocations = %v, want a sorted pair", ids)
	}
}

// The reconciler used to describe namespaces and systemd units it never created.
func TestPlanOnlyClaimsWhatItDoes(t *testing.T) {
	t.Parallel()
	operations, err := (FileReconciler{StateDir: t.TempDir()}).Plan(context.Background(), fixtureState())
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range operations {
		switch operation.Kind {
		case "namespace", "veth", "systemd", "nftables", "dns":
			t.Fatalf("this reconciler does not perform %q operations", operation.Kind)
		}
	}
}

func TestRevisionStoreKeepsDesiredDevices(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	state := fixtureState()
	state.Devices = append(state.Devices, domain.DeployedDevice{ID: "phone"})
	store := FileRevisionStore{StateDir: directory}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Devices) != 2 {
		t.Fatalf("desired device count = %d, want 2", len(loaded.Devices))
	}
}

func fixtureState() domain.DesiredState {
	return domain.DesiredState{
		Revision: "revision", GeneratedAt: time.Now().UTC(),
		Devices: []domain.DeployedDevice{{ID: "macbook"}},
		Tunnels: []domain.Tunnel{{ID: "xray", Type: domain.TunnelXray, Role: domain.RoleEgress}},
	}
}
