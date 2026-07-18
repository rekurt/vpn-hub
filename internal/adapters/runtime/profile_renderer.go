package runtime

import (
	"fmt"
	"sort"
	"strings"

	"vpn-hub/internal/domain"
)

type AmneziaProfileRenderer struct{}

func (AmneziaProfileRenderer) Render(hub domain.Hub, profile domain.DeviceProfile) (string, error) {
	if profile.ClientPrivateKey == "" {
		return "", fmt.Errorf("client private key is required")
	}

	var builder strings.Builder
	builder.WriteString("[Interface]\n")
	builder.WriteString("PrivateKey = " + profile.ClientPrivateKey + "\n")
	builder.WriteString("Address = " + profile.Address + "\n")
	builder.WriteString("DNS = " + hub.DNSAddress + "\n")

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

	builder.WriteString("\n[Peer]\n")
	builder.WriteString("PublicKey = " + hub.ServerPublicKey + "\n")
	builder.WriteString("AllowedIPs = 0.0.0.0/0\n")
	builder.WriteString("Endpoint = " + hub.Endpoint + "\n")
	builder.WriteString("PersistentKeepalive = 25\n")
	return builder.String(), nil
}
