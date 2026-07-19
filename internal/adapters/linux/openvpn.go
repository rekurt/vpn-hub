package linux

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"vpn-hub/internal/domain"
)

// OpenVPNManagementSocket is where the process reports its state. A unix socket
// rather than the log: the log is prose meant for people and changes between
// releases, while this is an interface with a documented vocabulary.
func OpenVPNManagementSocket(runtimeDir, tunnelID string) string {
	return filepath.Join(runtimeDir, tunnelID+"-openvpn.sock")
}

// RenderOpenVPNConfig takes the provider's file and appends only what the hub needs
// to hold true.
//
// Everything the provider wrote is preserved: OpenVPN understands its own options
// better than a reimplementation would, and providers use plenty this hub has no
// business second-guessing. The additions are the parts the hub cannot leave to
// chance -- which device to create, where to report state, and not to daemonise,
// since systemd supervises it.
func RenderOpenVPNConfig(tunnel domain.OpenVPNTunnel, device, managementSocket string) string {
	var out strings.Builder
	out.WriteString(tunnel.Config)
	if !strings.HasSuffix(tunnel.Config, "\n") {
		out.WriteString("\n")
	}

	out.WriteString("\n# Appended by vpn-hub. The provider's own options above are untouched.\n")
	// A fixed name so the reconciler and the routing it installs agree on it.
	fmt.Fprintf(&out, "dev %s\n", device)
	out.WriteString("dev-type tun\n")
	// systemd supervises the process; daemonising would hide its exit from the unit.
	out.WriteString("nobind\n")
	fmt.Fprintf(&out, "management %s unix\n", managementSocket)
	out.WriteString("management-client-user root\n")
	// The namespace is the isolation boundary, so dropping privileges inside it buys
	// nothing and prevents OpenVPN from configuring its own device.
	out.WriteString("script-security 0\n")
	return out.String()
}

// ensureOpenVPN runs the provider's client inside the namespace.
func (e Egress) ensureOpenVPN(ctx context.Context, spec domain.EgressSpec) error {
	socket := OpenVPNManagementSocket(e.secretsDir(), spec.TunnelID)
	config := RenderOpenVPNConfig(spec.OpenVPN, spec.Interface, socket)

	path := filepath.Join(e.secretsDir(), spec.TunnelID+"-openvpn.conf")
	// 0600: the file carries the provider's inline keys.
	changed, err := writeIfChanged(path, config, 0o600)
	if err != nil {
		return err
	}

	unit := "vpn-hub-openvpn-" + spec.TunnelID
	if !changed {
		if _, err := e.run(ctx, "systemctl", "is-active", "--quiet", unit+".service"); err == nil {
			return e.ensureOpenVPNRoutes(ctx, spec)
		}
	}
	// The remote must be reachable without going through the tunnel being built:
	// ensureOpenVPNRoutes replaces the namespace default with the tun device, and
	// OpenVPN's own socket would then follow it straight back into itself.
	if err := e.ensureRemoteRoutes(ctx, spec); err != nil {
		return err
	}

	_, _ = e.run(ctx, "systemctl", "stop", unit+".service")
	if _, err := e.run(ctx, "systemd-run", "--quiet", "--collect", "--unit="+unit,
		"--property=Restart=on-failure", "--property=RestartSec=5s",
		"ip", "netns", "exec", spec.Namespace,
		"openvpn", "--config", path); err != nil {
		return err
	}
	return e.ensureOpenVPNRoutes(ctx, spec)
}

// ensureRemoteRoutes pins each provider address to the veth.
//
// Names are resolved here, in the main namespace, because that is where a working
// resolver is: the tunnel namespace has none until the tunnel it is trying to build
// comes up.
func (e Egress) ensureRemoteRoutes(ctx context.Context, spec domain.EgressSpec) error {
	gateway := hostOf(spec.HostAddress)
	for _, remote := range spec.OpenVPN.Remotes {
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", remote.Host)
		if err != nil {
			return fmt.Errorf("resolve provider %s: %w", remote.Host, err)
		}
		for _, address := range addresses {
			if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "route", "replace",
				address.String()+"/32", "via", gateway, "dev", spec.PeerVeth); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureOpenVPNRoutes waits for the device the provider's client creates. OpenVPN
// negotiates before it appears, so this is retried rather than assumed.
func (e Egress) ensureOpenVPNRoutes(ctx context.Context, spec domain.EgressSpec) error {
	var lastErr error
	for range 30 {
		_, lastErr = e.run(ctx, "ip", "-n", spec.Namespace, "link", "show", spec.Interface)
		if lastErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("openvpn did not create %s in %s: %w", spec.Interface, spec.Namespace, lastErr)
	}

	// OpenVPN installs its own routes when the provider asks for redirect-gateway.
	// Replacing the default unconditionally keeps the namespace's only way out the
	// tunnel either way, which is what makes it a kill switch.
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "route", "replace",
		"default", "dev", spec.Interface); err != nil {
		return err
	}
	return e.ensureNamespaceNAT(ctx, spec)
}

// OpenVPNState asks the management socket what the connection is doing.
//
// The vocabulary is OpenVPN's own: CONNECTED means the tunnel is up, and anything
// else names the stage it is stuck at, which is far more useful than "not working".
func OpenVPNState(socket string, timeout time.Duration) (string, error) {
	connection, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return "", fmt.Errorf("the management socket is not answering: %w", err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := connection.Write([]byte("state\n")); err != nil {
		return "", fmt.Errorf("ask for state: %w", err)
	}

	buffer := make([]byte, 4096)
	read, err := connection.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("read state: %w", err)
	}
	return parseOpenVPNState(string(buffer[:read]))
}

// parseOpenVPNState reads the state line, whose second field is the stage.
func parseOpenVPNState(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ">") || line == "END" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) >= 2 && fields[1] != "" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("the management socket reported no state")
}
