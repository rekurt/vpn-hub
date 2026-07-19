package linux

import (
	"fmt"
	"strconv"
	"strings"

	"vpn-hub/internal/domain"
)

// ParseWireGuardConfig reads a provider's .conf file.
//
// The format is the INI-like one wg-quick accepts. Only the fields the hub acts on
// are interpreted; anything else is ignored rather than rejected, because providers
// routinely ship extra keys and refusing them would make perfectly good
// configurations unusable.
//
// It is a pure function, so the parsing of real provider files is tested without
// touching a network.
func ParseWireGuardConfig(content string) (domain.WireGuardTunnel, error) {
	var tunnel domain.WireGuardTunnel
	section := ""
	seenPeer := false

	for number, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section == "peer" {
				if seenPeer {
					// Multiple peers would mean choosing one silently.
					return domain.WireGuardTunnel{}, fmt.Errorf("line %d: more than one [Peer]; an egress tunnel must name exactly one", number+1)
				}
				seenPeer = true
			}
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			return domain.WireGuardTunnel{}, fmt.Errorf("line %d: %q is not key = value", number+1, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				tunnel.PrivateKey = value
			case "address":
				tunnel.Addresses = splitList(value)
			case "dns":
				tunnel.DNS = splitList(value)
			case "mtu":
				mtu, err := strconv.Atoi(value)
				if err != nil {
					return domain.WireGuardTunnel{}, fmt.Errorf("line %d: invalid MTU %q", number+1, value)
				}
				tunnel.MTU = mtu
			default:
				// AmneziaWG carries its obfuscation settings in the [Interface]
				// section alongside the standard keys. They are collected here, under
				// their canonical spelling, so the egress driver can hand them to
				// `awg set`. A non-obfuscation key falls through and is ignored, as
				// any other unknown key is.
				if canonical, ok := domain.CanonicalAWGParameter(key); ok {
					if tunnel.Parameters == nil {
						tunnel.Parameters = make(map[string]string)
					}
					tunnel.Parameters[canonical] = value
				}
			}
		case "peer":
			switch key {
			case "publickey":
				tunnel.Peer.PublicKey = value
			case "presharedkey":
				tunnel.Peer.PresharedKey = value
			case "endpoint":
				tunnel.Peer.Endpoint = value
			case "allowedips":
				tunnel.Peer.AllowedIPs = splitList(value)
			case "persistentkeepalive":
				keepalive, err := strconv.Atoi(value)
				if err != nil {
					return domain.WireGuardTunnel{}, fmt.Errorf("line %d: invalid PersistentKeepalive %q", number+1, value)
				}
				tunnel.Peer.Keepalive = keepalive
			}
		}
	}

	return tunnel, validateTunnelConfig(tunnel)
}

func validateTunnelConfig(tunnel domain.WireGuardTunnel) error {
	var missing []string
	if tunnel.PrivateKey == "" {
		missing = append(missing, "Interface.PrivateKey")
	}
	if len(tunnel.Addresses) == 0 {
		missing = append(missing, "Interface.Address")
	}
	if tunnel.Peer.PublicKey == "" {
		missing = append(missing, "Peer.PublicKey")
	}
	if tunnel.Peer.Endpoint == "" {
		missing = append(missing, "Peer.Endpoint")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the configuration is missing %s", strings.Join(missing, ", "))
	}
	if err := domain.ValidatePublicKey(tunnel.Peer.PublicKey); err != nil {
		return fmt.Errorf("Peer.PublicKey: %w", err)
	}
	if _, err := domain.PublicKeyFromPrivate(tunnel.PrivateKey); err != nil {
		return fmt.Errorf("Interface.PrivateKey: %w", err)
	}
	return nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
