package linux

import (
	"context"
	"fmt"

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

	if _, err := e.run(ctx, "systemctl", "is-active", "--quiet", unit+".service"); err == nil {
		return nil
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
