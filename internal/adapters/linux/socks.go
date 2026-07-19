package linux

import (
	"context"
	"fmt"
	"strings"

	"vpn-hub/internal/domain"
)

// ensureSocks runs a SOCKS5 proxy inside the tunnel's namespace, listening on the
// namespace end of the link.
//
// microsocks comes from the Ubuntu archive rather than being written here: a proxy
// is a small thing to get right and a smaller thing to get subtly wrong, and the
// isolation that matters is the namespace, which it inherits by running inside one.
func (e Egress) ensureSocks(ctx context.Context, spec domain.EgressSpec) error {
	if spec.SocksPort == 0 {
		return nil
	}

	unit := "vpn-hub-socks-" + spec.TunnelID
	// Bound to the namespace end of the link, so the only route to it is across the
	// veth from the hub, where the firewall admits the client subnet alone.
	listen := hostOf(spec.PeerAddress)

	// Running is not enough: it has to be running on the address and port this
	// revision expects. Both are derived from the tunnel's position in the plan, so
	// removing another tunnel renumbers this one, and `ip addr replace` leaves the
	// old address in place -- the proxy would go on serving happily at an address
	// nothing forwards to any more, and no later reconcile would notice.
	if current, err := e.run(ctx, "systemctl", "show", "--property=ExecStart", "--value", unit+".service"); err == nil {
		if _, active := e.run(ctx, "systemctl", "is-active", "--quiet", unit+".service"); active == nil &&
			strings.Contains(current, "-i "+listen) && strings.Contains(current, "-p "+fmt.Sprint(spec.SocksPort)) {
			return nil
		}
	}

	_, _ = e.run(ctx, "systemctl", "stop", unit+".service")
	_, err := e.run(ctx, "systemd-run", "--quiet", "--collect", "--unit="+unit,
		"--property=Restart=on-failure", "--property=RestartSec=5s",
		"ip", "netns", "exec", spec.Namespace,
		"microsocks", "-i", listen, "-p", fmt.Sprint(spec.SocksPort))
	return err
}

// forwardSocks makes the hub's end of the link answer on the same port, since a
// client cannot reach inside a namespace.
func (e Egress) forwardSocks(ctx context.Context, spec domain.EgressSpec) error {
	if spec.SocksPort == 0 {
		return nil
	}
	ruleset := fmt.Sprintf(`table inet vpn_hub_socks_%s
delete table inet vpn_hub_socks_%s

table inet vpn_hub_socks_%s {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr %s tcp dport %d dnat ip to %s:%d
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip daddr %s tcp dport %d masquerade
	}
}
`, safeTableName(spec.TunnelID), safeTableName(spec.TunnelID), safeTableName(spec.TunnelID),
		hostOf(spec.HostAddress), spec.SocksPort, hostOf(spec.PeerAddress), spec.SocksPort,
		hostOf(spec.PeerAddress), spec.SocksPort)

	return e.applyRuleset(ctx, ruleset)
}

func safeTableName(tunnelID string) string {
	return internalSetName(tunnelID)[len("internal_"):]
}
