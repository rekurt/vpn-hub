package linux

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PeerSpec is one client profile as the ingress interface should hold it.
type PeerSpec struct {
	PublicKey  string
	AllowedIPs []string
}

// IngressSpec describes the AmneziaWG interface the hub presents to clients.
type IngressSpec struct {
	Interface  string
	Address    string
	ListenPort uint16
	// PrivateKey is written to a file under SecretsDir rather than passed as an
	// argument, because argv is world-readable through /proc.
	PrivateKey string
	// Parameters are the obfuscation knobs, already validated and canonicalised.
	Parameters map[string]string
	Peers      []PeerSpec
}

// runner executes a host command, optionally feeding it stdin. Tests substitute a
// fake so the adapter's command sequence can be asserted without root or Linux.
type runner func(ctx context.Context, name string, args ...string) (string, error)

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
		}
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// Ingress manages the AmneziaWG interface that clients connect to.
//
// It drives the `ip` and `awg` binaries rather than wgctrl: the amneziawg kernel
// module registers its own netlink family, and both `wg` and wgctrl answer
// "Operation not supported" for these devices.
type Ingress struct {
	// Run defaults to executing commands for real.
	Run runner
	// SecretsDir must be on tmpfs; the agent's RuntimeDirectory (/run/vpn-hub) is.
	SecretsDir string
}

func (i Ingress) run(ctx context.Context, name string, args ...string) (string, error) {
	if i.Run != nil {
		return i.Run(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

// Observe reports what the host currently has. A missing interface is not an error:
// it is the state before the first reconcile.
func (i Ingress) Observe(ctx context.Context, name string) (IngressState, error) {
	output, err := i.run(ctx, "awg", "show", name, "dump")
	if err != nil {
		return IngressState{}, nil //nolint:nilerr // absent interface, not a failure
	}
	return ParseDump(output)
}

// Apply converges the interface towards spec. Every step is idempotent, so a repeated
// reconcile is a no-op rather than a rebuild that would drop client sessions.
func (i Ingress) Apply(ctx context.Context, spec IngressSpec) error {
	if spec.Interface == "" || spec.Address == "" || spec.PrivateKey == "" {
		return fmt.Errorf("ingress interface, address and private key are required")
	}

	observed, err := i.Observe(ctx, spec.Interface)
	if err != nil {
		return err
	}
	if !observed.Exists {
		if _, err := i.run(ctx, "ip", "link", "add", "dev", spec.Interface, "type", "amneziawg"); err != nil {
			return err
		}
	}

	keyPath, err := i.writePrivateKey(spec)
	if err != nil {
		return err
	}

	arguments := []string{"set", spec.Interface, "private-key", keyPath, "listen-port", strconv.Itoa(int(spec.ListenPort))}
	for _, name := range sortedKeys(spec.Parameters) {
		arguments = append(arguments, strings.ToLower(name), spec.Parameters[name])
	}
	if _, err := i.run(ctx, "awg", arguments...); err != nil {
		return err
	}

	if err := i.syncPeers(ctx, spec, observed); err != nil {
		return err
	}

	// `addr replace` is idempotent where `addr add` would fail on the second pass.
	if _, err := i.run(ctx, "ip", "addr", "replace", spec.Address, "dev", spec.Interface); err != nil {
		return err
	}
	_, err = i.run(ctx, "ip", "link", "set", spec.Interface, "up")
	return err
}

// syncPeers adds or updates the configured peers and removes the rest, so a revoked
// device stops being able to complete a handshake.
func (i Ingress) syncPeers(ctx context.Context, spec IngressSpec, observed IngressState) error {
	wanted := make(map[string]struct{}, len(spec.Peers))
	for _, peer := range spec.Peers {
		wanted[peer.PublicKey] = struct{}{}
		if _, err := i.run(ctx, "awg", "set", spec.Interface,
			"peer", peer.PublicKey,
			"allowed-ips", strings.Join(peer.AllowedIPs, ",")); err != nil {
			return err
		}
	}

	for _, peer := range observed.Peers {
		if _, keep := wanted[peer.PublicKey]; keep {
			continue
		}
		if _, err := i.run(ctx, "awg", "set", spec.Interface, "peer", peer.PublicKey, "remove"); err != nil {
			return err
		}
	}
	return nil
}

func (i Ingress) writePrivateKey(spec IngressSpec) (string, error) {
	directory := i.SecretsDir
	if directory == "" {
		directory = "/run/vpn-hub"
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create secrets directory: %w", err)
	}
	path := filepath.Join(directory, spec.Interface+".key")
	if err := os.WriteFile(path, []byte(spec.PrivateKey+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	return path, nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
