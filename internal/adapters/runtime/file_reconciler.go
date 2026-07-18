package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"vpn-hub/internal/domain"
)

const (
	desiredStateFile = "desired-state.json"
	activeStateFile  = "active-state.json"
	revokedStateFile = "revoked-devices.json"
)

type FileReconciler struct {
	StateDir string
}

func (r FileReconciler) Plan(_ context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	state, err := r.filterRevoked(state)
	if err != nil {
		return nil, err
	}
	operations := []domain.Operation{
		{Kind: "nftables", Resource: "inet vpn_hub", Description: "install isolated marks, connmark and kill-switch rules", Command: "nft -f /run/vpn-hub/nftables.nft"},
		{Kind: "dns", Resource: "vpn-hub-dns", Description: "install split DNS forwarders and nft sets", Command: "systemctl reload vpn-hub-dns"},
	}

	tunnels := append([]domain.Tunnel(nil), state.Tunnels...)
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })
	for _, tunnel := range tunnels {
		namespace := "vpn-hub-" + tunnel.ID
		operations = append(operations,
			domain.Operation{Kind: "namespace", Resource: namespace, Description: "create isolated network namespace", Command: "ip netns add " + namespace},
			domain.Operation{Kind: "veth", Resource: tunnel.ID, Description: "create hub-to-tunnel veth pair and policy route", Command: "ip link add veth-" + tunnel.ID + " type veth peer name eth0 netns " + namespace},
			domain.Operation{Kind: "systemd", Resource: "vpn-hub-tunnel@" + tunnel.ID, Description: "start isolated " + string(tunnel.Type) + " tunnel", Command: "systemctl restart vpn-hub-tunnel@" + tunnel.ID},
		)
	}
	return operations, nil
}

func (r FileReconciler) Apply(ctx context.Context, state domain.DesiredState) error {
	if r.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	filtered, err := r.filterRevoked(state)
	if err != nil {
		return err
	}
	if _, err := r.Plan(ctx, filtered); err != nil {
		return err
	}
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(r.StateDir)
	if err != nil {
		return err
	}
	defer release()
	data, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal active state: %w", err)
	}
	return atomicWrite(filepath.Join(r.StateDir, activeStateFile), data, 0o600)
}

type FileRevisionStore struct {
	StateDir string
}

func (s FileRevisionStore) Save(ctx context.Context, state domain.DesiredState) error {
	if s.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(s.StateDir)
	if err != nil {
		return err
	}
	defer release()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal desired state: %w", err)
	}
	return atomicWrite(filepath.Join(s.StateDir, desiredStateFile), data, 0o600)
}

func (s FileRevisionStore) Load(_ context.Context) (domain.DesiredState, error) {
	data, err := os.ReadFile(filepath.Join(s.StateDir, desiredStateFile))
	if err != nil {
		return domain.DesiredState{}, fmt.Errorf("read desired state: %w", err)
	}
	var state domain.DesiredState
	if err := json.Unmarshal(data, &state); err != nil {
		return domain.DesiredState{}, fmt.Errorf("decode desired state: %w", err)
	}
	return state, nil
}

func (r FileReconciler) filterRevoked(state domain.DesiredState) (domain.DesiredState, error) {
	if r.StateDir == "" {
		return state, nil
	}
	data, err := os.ReadFile(filepath.Join(r.StateDir, revokedStateFile))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return domain.DesiredState{}, fmt.Errorf("read revoked devices: %w", err)
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return domain.DesiredState{}, fmt.Errorf("decode revoked devices: %w", err)
	}
	revoked := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		revoked[id] = struct{}{}
	}
	filtered := state
	filtered.Devices = make([]domain.DeployedDevice, 0, len(state.Devices))
	for _, device := range state.Devices {
		if _, isRevoked := revoked[device.ID]; !isRevoked {
			filtered.Devices = append(filtered.Devices, device)
		}
	}
	return filtered, nil
}
