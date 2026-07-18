package application

import (
	"testing"

	"vpn-hub/internal/domain"
)

func TestRemoveRevokedDropsTheDevice(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	cfg.Devices = append(cfg.Devices, domain.Device{ID: "phone"})

	result := RemoveRevoked(cfg, []string{"phone"})
	if len(result.Devices) != 1 || result.Devices[0].ID != "macbook" {
		t.Fatalf("devices = %+v, want only macbook", result.Devices)
	}
}

// Pruning a revoked ID out of AllowedDevices could empty the list, and an empty list
// means "every device is allowed" — so revoking would have widened the ACL instead of
// tightening it.
func TestRemoveRevokedNeverWidensAnEgressACL(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)

	before := len(cfg.Tunnels[1].AllowedDevices)
	if before == 0 {
		t.Fatal("fixture must have a tunnel with a non-empty ACL")
	}

	result := RemoveRevoked(cfg, []string{"macbook"})
	if got := len(result.Tunnels[1].AllowedDevices); got != before {
		t.Fatalf("ACL length changed from %d to %d; an emptied ACL would allow everyone", before, got)
	}
}

func TestRemoveRevokedIsANoOpWithoutRevocations(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	if got := len(RemoveRevoked(cfg, nil).Devices); got != len(cfg.Devices) {
		t.Fatalf("device count = %d, want %d", got, len(cfg.Devices))
	}
}

// The pruned configuration is what a revision gets compiled from, so it has to
// survive that step.
func TestDesiredStateBuildsFromAPrunedConfig(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	if err := Validate(cfg); err != nil {
		t.Fatalf("fixture must validate: %v", err)
	}

	state, err := Service{}.BuildDesiredState(RemoveRevoked(cfg, []string{"macbook"}))
	if err != nil {
		t.Fatalf("BuildDesiredState after revocation: %v", err)
	}
	if len(state.Devices) != 0 {
		t.Fatalf("revoked device survived into the revision: %+v", state.Devices)
	}
}
