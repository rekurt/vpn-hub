package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpn-hub/internal/domain"
)

// Egress runs each upstream tunnel inside its own network namespace.
//
// Isolation is the point: a provider's configuration routinely asks for a default
// route and its own DNS, and inside a namespace it can have both without touching
// the main routing table or another provider's.
type Egress struct {
	Run        runner
	SecretsDir string
	// RulePriority is where the fwmark rules sit. It is above the main table's
	// implicit rule so marked traffic is diverted before ordinary routing sees it.
	RulePriority int
	// DirectNamespaces calls `ip netns` without delegating to a transient unit. Set
	// it where there is no sandbox to escape -- integration tests, and hosts without
	// systemd -- since delegation buys nothing there.
	DirectNamespaces bool
}

func (e Egress) run(ctx context.Context, name string, args ...string) (string, error) {
	if e.Run != nil {
		return e.Run(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

// inNS prefixes a command so it runs inside the tunnel's namespace.
func (e Egress) inNS(ctx context.Context, namespace string, args ...string) (string, error) {
	return e.run(ctx, "ip", append([]string{"netns", "exec", namespace}, args...)...)
}

// namespaceLifecycle runs `ip netns add|del` through a transient systemd unit.
//
// Creating or deleting a network namespace is a bind mount under /run/netns, and the
// agent runs with a private mount namespace. A mount made there is confined to the
// service and unusable even by its own later commands -- the namespace appears to
// exist and every operation on it fails with "Invalid argument".
//
// A transient unit performs the mount in the host's mount namespace, from where it
// propagates back in: systemd mounts with MS_SLAVE, so host mounts are visible to
// the service while the service's own are not visible outside. That asymmetry is
// what lets the agent keep ProtectSystem=strict and still manage namespaces.
func (e Egress) namespaceLifecycle(ctx context.Context, action, namespace string) error {
	if e.DirectNamespaces {
		_, err := e.run(ctx, "ip", "netns", action, namespace)
		return err
	}
	_, err := e.run(ctx, "systemd-run",
		"--quiet", "--wait", "--collect", "--unit=vpn-hub-netns-"+action+"-"+namespace,
		"ip", "netns", action, namespace)
	return err
}

func (e Egress) rulePriority() int {
	if e.RulePriority != 0 {
		return e.RulePriority
	}
	return 1000
}

// Observe lists the namespaces the hub currently owns.
func (e Egress) Observe(ctx context.Context) ([]string, error) {
	output, err := e.run(ctx, "ip", "-j", "netns", "list")
	if err != nil {
		return nil, nil //nolint:nilerr // no namespaces yet is not a failure
	}
	return parseNamespaces(output)
}

// Apply converges every egress namespace and removes any the revision dropped.
func (e Egress) Apply(ctx context.Context, specs []domain.EgressSpec) error {
	wanted := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		wanted[spec.Namespace] = struct{}{}
		if err := e.applyOne(ctx, spec); err != nil {
			return fmt.Errorf("egress %s: %w", spec.TunnelID, err)
		}
	}

	existing, err := e.Observe(ctx)
	if err != nil {
		return err
	}
	for _, namespace := range existing {
		if !strings.HasPrefix(namespace, "vpn-hub-") {
			continue // not ours
		}
		if _, keep := wanted[namespace]; keep {
			continue
		}
		// Stop the proxy first: deleting a namespace out from under a running
		// process leaves the unit failing in a loop rather than simply gone.
		_, _ = e.run(ctx, "systemctl", "stop",
			"vpn-hub-proxy-"+strings.TrimPrefix(namespace, "vpn-hub-")+".service")
		// Deleting the namespace takes its interfaces, routes and processes with it.
		if err := e.namespaceLifecycle(ctx, "del", namespace); err != nil {
			return fmt.Errorf("remove namespace %s: %w", namespace, err)
		}
	}
	return nil
}

func (e Egress) applyOne(ctx context.Context, spec domain.EgressSpec) error {
	if err := e.ensureNamespace(ctx, spec); err != nil {
		return err
	}
	if err := e.ensureLink(ctx, spec); err != nil {
		return err
	}
	if err := e.ensureTunnel(ctx, spec); err != nil {
		return err
	}
	return e.ensurePolicyRouting(ctx, spec)
}

func (e Egress) ensureNamespace(ctx context.Context, spec domain.EgressSpec) error {
	existing, err := e.Observe(ctx)
	if err != nil {
		return err
	}
	present := false
	for _, namespace := range existing {
		if namespace == spec.Namespace {
			present = true
			break
		}
	}

	// A crash partway through `ip netns add` leaves the handle in /run/netns without
	// its bind mount. It then looks present but every operation on it fails, and
	// `ip netns add` will not replace it, so the hub would stay wedged until someone
	// cleaned up by hand. Prove it works before trusting it.
	if present {
		if _, err := e.inNS(ctx, spec.Namespace, "true"); err != nil {
			if err := e.namespaceLifecycle(ctx, "del", spec.Namespace); err != nil {
				return fmt.Errorf("remove unusable namespace %s: %w", spec.Namespace, err)
			}
			present = false
		}
	}

	if !present {
		if err := e.namespaceLifecycle(ctx, "add", spec.Namespace); err != nil {
			return err
		}
	}
	// Applied every pass, not only at creation: these are exactly the kind of setting
	// someone reaches for when debugging, and they must not stay changed.
	return e.enableForwarding(ctx, spec.Namespace)
}

// enableForwarding turns on IPv4 forwarding inside the namespace and keeps IPv6 off.
//
// These are per-namespace settings: a fresh namespace starts with forwarding
// disabled regardless of the host, and this namespace exists precisely to forward
// client traffic into the tunnel.
func (e Egress) enableForwarding(ctx context.Context, namespace string) error {
	for _, setting := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv6.conf.all.disable_ipv6=1",
		"net.ipv6.conf.default.disable_ipv6=1",
	} {
		if _, err := e.inNS(ctx, namespace, "sysctl", "-qw", setting); err != nil {
			return fmt.Errorf("set %s in %s: %w", setting, namespace, err)
		}
	}
	return nil
}

// ensureLink builds the veth pair joining the main namespace to the tunnel's.
func (e Egress) ensureLink(ctx context.Context, spec domain.EgressSpec) error {
	// A missing host side means the pair is absent: deleting either end removes both.
	if _, err := e.run(ctx, "ip", "link", "show", spec.HostVeth); err != nil {
		if _, err := e.run(ctx, "ip", "link", "add", spec.HostVeth,
			"type", "veth", "peer", "name", spec.PeerVeth); err != nil {
			return err
		}
		if _, err := e.run(ctx, "ip", "link", "set", spec.PeerVeth, "netns", spec.Namespace); err != nil {
			return err
		}
	}

	if _, err := e.run(ctx, "ip", "addr", "replace", spec.HostAddress, "dev", spec.HostVeth); err != nil {
		return err
	}
	if _, err := e.run(ctx, "ip", "link", "set", spec.HostVeth, "up"); err != nil {
		return err
	}
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "addr", "replace", spec.PeerAddress, "dev", spec.PeerVeth); err != nil {
		return err
	}
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "set", spec.PeerVeth, "up"); err != nil {
		return err
	}
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "set", "lo", "up"); err != nil {
		return err
	}

	// Returning client traffic has to find its way back across the link.
	gateway := hostOf(spec.HostAddress)
	_, err := e.run(ctx, "ip", "-n", spec.Namespace, "route", "replace",
		spec.ClientCIDR, "via", gateway, "dev", spec.PeerVeth)
	return err
}

// ensureTunnel brings the upstream interface up inside the namespace, by whichever
// mechanism the tunnel's protocol needs.
func (e Egress) ensureTunnel(ctx context.Context, spec domain.EgressSpec) error {
	if spec.Type == domain.TunnelXray {
		return e.ensureProxy(ctx, spec)
	}
	return e.ensureWireGuard(ctx, spec)
}

// ensureProxy runs sing-box inside the namespace, presenting a tun device that
// ordinary routing can send packets to.
func (e Egress) ensureProxy(ctx context.Context, spec domain.EgressSpec) error {
	// sing-box's own connections to the provider must leave through the veth, not
	// through the tun device it serves. They carry a mark; this rule acts on it.
	if err := e.ensureProxyEscapeRoute(ctx, spec); err != nil {
		return err
	}

	config, err := RenderSingBoxConfig(spec.Proxy)
	if err != nil {
		return err
	}
	path := filepath.Join(e.secretsDir(), spec.TunnelID+"-singbox.json")
	// 0600: the file holds the UUID that authenticates the hub to the provider.
	changed, err := writeIfChanged(path, config, 0o600)
	if err != nil {
		return err
	}

	unit := "vpn-hub-proxy-" + spec.TunnelID
	if !changed {
		if _, err := e.run(ctx, "systemctl", "is-active", "--quiet", unit+".service"); err == nil {
			return e.ensureProxyRoutes(ctx, spec)
		}
	}
	_, _ = e.run(ctx, "systemctl", "stop", unit+".service")
	if _, err := e.run(ctx, "systemd-run", "--quiet", "--collect", "--unit="+unit,
		"--property=Restart=on-failure", "--property=RestartSec=5s",
		"ip", "netns", "exec", spec.Namespace,
		"sing-box", "run", "-c", path); err != nil {
		return err
	}
	return e.ensureProxyRoutes(ctx, spec)
}

// ensureProxyEscapeRoute gives sing-box's marked connections a way out of the
// namespace that does not pass through its own tun device.
func (e Egress) ensureProxyEscapeRoute(ctx context.Context, spec domain.EgressSpec) error {
	table := strconv.Itoa(SingBoxOutboundTable)
	mark := fmt.Sprintf("0x%x", SingBoxOutboundMark)

	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "route", "replace", "default",
		"via", hostOf(spec.HostAddress), "dev", spec.PeerVeth, "table", table); err != nil {
		return err
	}
	// `ip rule add` is not idempotent and would stack duplicates on every reconcile.
	existing, err := e.inNS(ctx, spec.Namespace, "ip", "rule", "show", "fwmark", mark)
	if err == nil && strings.Contains(existing, "lookup "+table) {
		return nil
	}
	_, err = e.inNS(ctx, spec.Namespace, "ip", "rule", "add", "fwmark", mark,
		"lookup", table, "priority", "100")
	return err
}

// ensureProxyRoutes waits for the tun device sing-box creates and routes through it.
// The device only exists once the process is up, so this is retried rather than
// assumed.
func (e Egress) ensureProxyRoutes(ctx context.Context, spec domain.EgressSpec) error {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "show", spec.Interface); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("sing-box did not create %s in %s: %w", spec.Interface, spec.Namespace, lastErr)
	}

	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "set", spec.Interface, "up"); err != nil {
		return err
	}
	// As with WireGuard, the only way out of this namespace is the tunnel: if
	// sing-box stops, its device goes and packets are discarded here.
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "route", "replace",
		"default", "dev", spec.Interface); err != nil {
		return err
	}
	return e.ensureNamespaceNAT(ctx, spec)
}

func (e Egress) ensureWireGuard(ctx context.Context, spec domain.EgressSpec) error {
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "show", spec.Interface); err != nil {
		// The interface is created in the main namespace and moved: a WireGuard
		// device keeps its socket in the namespace it was created in, which is how
		// it can still reach the internet from inside an otherwise isolated one.
		if _, err := e.run(ctx, "ip", "link", "add", spec.Interface, "type", "wireguard"); err != nil {
			return err
		}
		if _, err := e.run(ctx, "ip", "link", "set", spec.Interface, "netns", spec.Namespace); err != nil {
			return err
		}
	}

	keyPath, err := e.writeKey(spec.TunnelID+"-private", spec.Tunnel.PrivateKey)
	if err != nil {
		return err
	}
	arguments := []string{"wg", "set", spec.Interface, "private-key", keyPath,
		"peer", spec.Tunnel.Peer.PublicKey,
		"endpoint", spec.Tunnel.Peer.Endpoint,
		"allowed-ips", strings.Join(allowedOrDefault(spec.Tunnel.Peer.AllowedIPs), ",")}
	if spec.Tunnel.Peer.PresharedKey != "" {
		pskPath, err := e.writeKey(spec.TunnelID+"-psk", spec.Tunnel.Peer.PresharedKey)
		if err != nil {
			return err
		}
		arguments = append(arguments, "preshared-key", pskPath)
	}
	if spec.Tunnel.Peer.Keepalive > 0 {
		arguments = append(arguments, "persistent-keepalive", strconv.Itoa(spec.Tunnel.Peer.Keepalive))
	}
	if _, err := e.inNS(ctx, spec.Namespace, arguments...); err != nil {
		return err
	}
	// An egress tunnel has exactly one peer, and its allowed-ips is usually
	// 0.0.0.0/0. A peer left over from an earlier configuration would claim the same
	// range, making the route ambiguous and sending traffic to whichever matched
	// first -- possibly an endpoint the operator has since replaced.
	if err := e.removeOtherPeers(ctx, spec); err != nil {
		return err
	}

	for _, address := range spec.Tunnel.Addresses {
		if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "addr", "replace", address, "dev", spec.Interface); err != nil {
			return err
		}
	}
	if spec.Tunnel.MTU > 0 {
		if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "set", spec.Interface,
			"mtu", strconv.Itoa(spec.Tunnel.MTU)); err != nil {
			return err
		}
	}
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "link", "set", spec.Interface, "up"); err != nil {
		return err
	}

	// The only way out of this namespace is the tunnel. If it drops, packets have
	// nowhere to go and are discarded here -- a second kill switch, independent of
	// the packet filter in the main namespace.
	if _, err := e.run(ctx, "ip", "-n", spec.Namespace, "route", "replace",
		"default", "dev", spec.Interface); err != nil {
		return err
	}

	return e.ensureNamespaceNAT(ctx, spec)
}

// ensureNamespaceNAT translates everything leaving through the tunnel to the address
// the provider issued. Not just the client subnet: the hub itself sends traffic this
// way too -- the resolver querying a private zone's nameserver arrives from this end
// of the veth -- and untranslated it would reach a network with no route back.
func (e Egress) ensureNamespaceNAT(ctx context.Context, spec domain.EgressSpec) error {
	ruleset := fmt.Sprintf(`table inet vpn_hub_egress
delete table inet vpn_hub_egress

table inet vpn_hub_egress {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname %q masquerade
	}
}
`, spec.Interface)
	return e.applyNamespaceRuleset(ctx, spec.Namespace, ruleset)
}

func (e Egress) removeOtherPeers(ctx context.Context, spec domain.EgressSpec) error {
	output, err := e.inNS(ctx, spec.Namespace, "wg", "show", spec.Interface, "dump")
	if err != nil {
		return nil //nolint:nilerr // nothing to prune if the interface cannot be read
	}
	observed, err := ParseDump(output)
	if err != nil {
		return fmt.Errorf("read peers of %s: %w", spec.Interface, err)
	}
	for _, peer := range observed.Peers {
		if peer.PublicKey == spec.Tunnel.Peer.PublicKey {
			continue
		}
		if _, err := e.inNS(ctx, spec.Namespace, "wg", "set", spec.Interface,
			"peer", peer.PublicKey, "remove"); err != nil {
			return err
		}
	}
	return nil
}

// ensurePolicyRouting steers marked traffic into this tunnel's table.
func (e Egress) ensurePolicyRouting(ctx context.Context, spec domain.EgressSpec) error {
	table := strconv.Itoa(spec.RouteTable)
	mark := fmt.Sprintf("0x%x", spec.Mark)

	// Via the namespace end rather than just "dev": on a /30 link a device-scoped
	// default makes the kernel resolve the destination address itself, and the peer
	// answers for nothing but its own.
	if _, err := e.run(ctx, "ip", "route", "replace", "default",
		"via", hostOf(spec.PeerAddress), "dev", spec.HostVeth, "table", table); err != nil {
		return err
	}

	// `ip rule add` is not idempotent and would stack duplicates on every reconcile.
	existing, err := e.run(ctx, "ip", "rule", "show", "fwmark", mark)
	if err == nil && strings.Contains(existing, "lookup "+table) {
		return nil
	}
	_, err = e.run(ctx, "ip", "rule", "add", "fwmark", mark,
		"lookup", table, "priority", strconv.Itoa(e.rulePriority()))
	return err
}

// applyNamespaceRuleset feeds a ruleset to nft inside a namespace. It bypasses the
// runner because that has no way to supply stdin, and a fake runner cannot verify
// the ruleset anyway -- the integration tests read it back from the namespace.
func (e Egress) applyNamespaceRuleset(ctx context.Context, namespace, ruleset string) error {
	if e.Run != nil {
		_, err := e.Run(ctx, "nft-in-netns", namespace, ruleset)
		return err
	}
	command := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nft", "-f", "-")
	command.Stdin = strings.NewReader(ruleset)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return fmt.Errorf("apply ruleset in %s: %w: %s", namespace, err, message)
		}
		return fmt.Errorf("apply ruleset in %s: %w", namespace, err)
	}
	return nil
}

func (e Egress) secretsDir() string {
	if e.SecretsDir != "" {
		return e.SecretsDir
	}
	return "/run/vpn-hub"
}

func (e Egress) writeKey(name, value string) (string, error) {
	path := filepath.Join(e.secretsDir(), name+".key")
	if _, err := writeIfChanged(path, value+"\n", 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// writeIfChanged reports whether the file's contents changed, so a process reading it
// is only restarted when there is a reason to.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create directory for %s: %w", path, err)
	}
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return false, nil
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

// allowedOrDefault treats an unset AllowedIPs as "everything", which is what an
// egress tunnel means.
func allowedOrDefault(allowed []string) []string {
	if len(allowed) == 0 {
		return []string{"0.0.0.0/0"}
	}
	return allowed
}

// hostOf strips the prefix length from an address.
func hostOf(address string) string {
	host, _, found := strings.Cut(address, "/")
	if !found {
		return address
	}
	return host
}

type namespaceEntry struct {
	Name string `json:"name"`
}

func parseNamespaces(output string) ([]string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || trimmed == "[]" {
		return nil, nil
	}
	var entries []namespaceEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return nil, fmt.Errorf("decode namespace list: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name != "" {
			names = append(names, entry.Name)
		}
	}
	return names, nil
}
