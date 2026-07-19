package linux

import (
	"encoding/base64"
	"fmt"
	"strings"

	"vpn-hub/internal/domain"
)

// ParseSubscription reads a provider's subscription payload.
//
// The convention is a list of share links, one per line, usually the whole document
// base64-encoded. Both forms appear in the wild, so both are accepted; anything that
// is not a link the hub can use is skipped rather than failing the batch, because a
// provider adding a protocol should not cost you the ones that still work.
//
// It is a pure function, so real payload shapes are tested without a network.
func ParseSubscription(payload []byte) ([]domain.ProxyTunnel, error) {
	text := strings.TrimSpace(string(payload))
	if text == "" {
		return nil, fmt.Errorf("the subscription is empty")
	}

	// A subscription is usually base64; a plain list is not. Decoding failure just
	// means it was already plain.
	if decoded, err := decodeBase64(text); err == nil {
		text = decoded
	}

	var tunnels []domain.ProxyTunnel
	var skipped int
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "vless://") {
			skipped++
			continue
		}
		tunnel, err := ParseVLESS(line)
		if err != nil {
			skipped++
			continue
		}
		tunnels = append(tunnels, tunnel)
	}

	if len(tunnels) == 0 {
		return nil, fmt.Errorf("the subscription holds no usable links (%d entries were of other kinds)", skipped)
	}
	return tunnels, nil
}

// decodeBase64 accepts both the padded and unpadded forms providers use.
func decodeBase64(text string) (string, error) {
	compact := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(text)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(compact); err == nil {
			// A decode that yields no link is a coincidence, not a subscription.
			if strings.Contains(string(decoded), "://") {
				return string(decoded), nil
			}
		}
	}
	return "", fmt.Errorf("not base64")
}
