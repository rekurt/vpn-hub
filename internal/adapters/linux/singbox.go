package linux

import (
	"encoding/json"
	"fmt"

	"vpn-hub/internal/domain"
)

// SingBoxTunInterface is the device sing-box creates inside the namespace. It can
// repeat across namespaces precisely because they are isolated.
const SingBoxTunInterface = "sb0"

// SingBoxTunAddress is the tun device's own address. It only has to be free inside
// the namespace, which holds nothing else.
const SingBoxTunAddress = "172.19.0.1/30"

// SingBoxOutboundMark labels the connections sing-box makes to its provider, so a
// rule inside the namespace can send them out of the veth instead of back into the
// tun device sing-box itself serves.
const SingBoxOutboundMark = 0x2

// SingBoxOutboundTable is the routing table that mark selects.
const SingBoxOutboundTable = 200

// RenderSingBoxConfig builds the configuration for one proxy tunnel.
//
// The tun inbound is what turns a proxy into something ordinary routing can use:
// packets arrive on a device, sing-box takes them from there. auto_route is off
// because the hub owns routing — letting sing-box install its own would fight the
// policy rules the reconciler places.
//
// The outbound is marked rather than bound to an interface. Binding sets the socket's
// device but does not give it a route, and the namespace's default route points at
// the tun device sing-box itself serves -- so a bound socket fails with "no route to
// host". A mark, paired with a rule inside the namespace, sends those connections out
// of the veth whatever the provider's address turns out to be.
func RenderSingBoxConfig(tunnel domain.ProxyTunnel) (string, error) {
	if tunnel.Protocol != "vless" {
		return "", fmt.Errorf("unsupported proxy protocol %q", tunnel.Protocol)
	}
	if tunnel.Server == "" || tunnel.Port == 0 || tunnel.UUID == "" {
		return "", fmt.Errorf("the proxy tunnel is missing a server, port or UUID")
	}

	outbound := map[string]any{
		"type":         "vless",
		"tag":          "proxy",
		"server":       tunnel.Server,
		"server_port":  tunnel.Port,
		"uuid":         tunnel.UUID,
		"routing_mark": SingBoxOutboundMark,
	}
	if tunnel.Flow != "" {
		outbound["flow"] = tunnel.Flow
	}

	if tunnel.TLS.Enabled {
		tls := map[string]any{"enabled": true}
		if tunnel.TLS.ServerName != "" {
			tls["server_name"] = tunnel.TLS.ServerName
		}
		if tunnel.TLS.Fingerprint != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": tunnel.TLS.Fingerprint}
		}
		if tunnel.TLS.Reality.Enabled {
			reality := map[string]any{"enabled": true, "public_key": tunnel.TLS.Reality.PublicKey}
			if tunnel.TLS.Reality.ShortID != "" {
				reality["short_id"] = tunnel.TLS.Reality.ShortID
			}
			tls["reality"] = reality
		}
		outbound["tls"] = tls
	}

	switch tunnel.Transport.Type {
	case "":
	case "ws", "httpupgrade":
		transport := map[string]any{"type": tunnel.Transport.Type, "path": tunnel.Transport.Path}
		if tunnel.Transport.Host != "" {
			transport["headers"] = map[string]any{"Host": tunnel.Transport.Host}
		}
		outbound["transport"] = transport
	case "grpc":
		outbound["transport"] = map[string]any{
			"type": "grpc", "service_name": tunnel.Transport.ServiceName,
		}
	default:
		return "", fmt.Errorf("unsupported transport %q", tunnel.Transport.Type)
	}

	config := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": false},
		"inbounds": []any{map[string]any{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": SingBoxTunInterface,
			"address":        []string{SingBoxTunAddress},
			"auto_route":     false,
			"sniff":          false,
		}},
		"outbounds": []any{outbound},
		"route": map[string]any{
			// Nothing to detect inside a namespace that holds one link.
			"auto_detect_interface": false,
		},
	}

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode sing-box configuration: %w", err)
	}
	return string(encoded) + "\n", nil
}
