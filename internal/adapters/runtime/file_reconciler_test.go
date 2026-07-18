package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

func TestFileReconcilerFiltersRevokedDevices(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	data, err := json.Marshal([]string{"phone"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, revokedStateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	state := fixtureState()
	state.Devices = append(state.Devices, domain.DeployedDevice{ID: "phone"})

	if err := (FileReconciler{StateDir: directory}).Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	active, err := readStateFile(filepath.Join(directory, activeStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Devices) != 1 || active.Devices[0].ID != "macbook" {
		t.Fatalf("active devices = %#v", active.Devices)
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

func readStateFile(path string) (domain.DesiredState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.DesiredState{}, err
	}
	var state domain.DesiredState
	err = json.Unmarshal(data, &state)
	return state, err
}
