package runtime

import (
	"fmt"
	"sort"
	"strings"

	"vpn-hub/internal/domain"
)

type AmneziaProfileRenderer struct{}

// defaultI1 is Amnezia's documented DNS-shaped client-side signature for
// AmneziaWG 1.5. It is sent before the handshake, which makes a profile less
// recognisable to DPI without requiring a matching server-side setting.
const defaultI1 = "<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>"

// Render builds a client profile. The private key is supplied by the caller rather
// than read from configuration: the hub stores only public keys, so the one moment a
// private key exists is when it is generated for a new device.
func (AmneziaProfileRenderer) Render(hub domain.Hub, address, privateKey string) (string, error) {
	if privateKey == "" {
		return "", fmt.Errorf("client private key is required")
	}
	if address == "" {
		return "", fmt.Errorf("client address is required")
	}

	var builder strings.Builder
	builder.WriteString("[Interface]\n")
	builder.WriteString("PrivateKey = " + privateKey + "\n")
	builder.WriteString("Address = " + address + "\n")
	builder.WriteString("DNS = " + hub.DNSAddress + "\n")
	// Cap the tunnel MTU rather than leave the client on its 1420 default. The client
	// reaches the hub across a path -- a mobile carrier, a link that shrinks packets --
	// whose MTU it cannot see, and a full-size encrypted datagram is dropped there
	// without warning: the handshake works while every larger packet, TCP or QUIC,
	// vanishes. The hub also clamps forwarded TCP MSS, but that cannot help UDP; a low
	// client MTU covers both. The value leaves headroom under a 1280-byte path for the
	// WireGuard and obfuscation overhead the datagram carries on top.
	builder.WriteString("MTU = 1240\n")

	// Emit the canonical spelling: configuration decoding lower-cases these keys, and
	// the client expects `Jc`, not `jc`. Validation has already rejected anything that
	// is not a known parameter with a numeric value.
	keys := make([]string, 0, len(hub.AWGInterface))
	for key := range hub.AWGInterface {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		name, known := domain.CanonicalAWGParameter(key)
		if !known {
			return "", fmt.Errorf("unsupported AmneziaWG parameter %q", key)
		}
		builder.WriteString(name + " = " + hub.AWGInterface[key] + "\n")
	}
	// I1 is deliberately profile-only. AmneziaWG treats signature packets as
	// optional pre-handshake camouflage, so adding it to a client does not alter
	// the ingress protocol or invalidate existing peers.
	builder.WriteString("I1 = " + defaultI1 + "\n")

	builder.WriteString("\n[Peer]\n")
	builder.WriteString("PublicKey = " + hub.ServerPublicKey + "\n")
	builder.WriteString("AllowedIPs = 0.0.0.0/0\n")
	builder.WriteString("Endpoint = " + hub.Endpoint + "\n")
	builder.WriteString("PersistentKeepalive = 25\n")
	return builder.String(), nil
}
