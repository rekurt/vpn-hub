package application

import "vpn-hub/internal/domain"

// RemoveRevoked drops revoked devices from a validated configuration, just before a
// desired state is built from it.
//
// Revocation has to take effect here rather than further downstream: the desired
// state is what the agent converges on, so a device that survives into it keeps its
// peer entry on the ingress interface and goes on handshaking.
//
// Egress ACLs are deliberately left alone. Pruning a revoked ID out of
// AllowedDevices could empty the list, and an empty list means "every device is
// allowed" — so tightening security would have silently widened it. A dangling entry
// is inert instead: the device is gone, and its profiles with it, so nothing can
// select that egress through it.
//
// The configuration must already have passed Validate; this only ever removes.
func RemoveRevoked(cfg domain.Config, revoked []string) domain.Config {
	if len(revoked) == 0 {
		return cfg
	}
	denied := make(map[string]struct{}, len(revoked))
	for _, id := range revoked {
		denied[id] = struct{}{}
	}

	result := cfg
	result.Devices = make([]domain.Device, 0, len(cfg.Devices))
	for _, device := range cfg.Devices {
		if _, isRevoked := denied[device.ID]; !isRevoked {
			result.Devices = append(result.Devices, device)
		}
	}
	return result
}
