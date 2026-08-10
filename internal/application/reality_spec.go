package application

import (
	"fmt"
	"sort"

	"vpn-hub/internal/domain"
)

// BuildRealityIngressSpec compiles the fallback listener from the revision.
//
// The marks come from the firewall plan rather than being recomputed, because the
// two must agree: a device whose listener outbound carries one mark while the
// packet filter steers that mark somewhere else would leave through a tunnel it
// never chose. Passing the plan in makes the shared numbering structural.
//
// A disabled fallback still returns a spec, with Enabled false. Turning it off has
// to reach the host and close the port; only "no spec at all" would be a no-op.
func BuildRealityIngressSpec(state domain.DesiredState, plan domain.FirewallPlan, privateKey string) (domain.RealityIngressSpec, error) {
	if !state.Hub.Fallback.Reality.Enabled {
		return domain.RealityIngressSpec{}, nil
	}
	if privateKey == "" {
		return domain.RealityIngressSpec{}, fmt.Errorf("the REALITY fallback is enabled but no key was provided")
	}
	publicKey, err := domain.RealityPublicKey(privateKey)
	if err != nil {
		return domain.RealityIngressSpec{}, err
	}

	marks := make(map[string]uint32, len(plan.Egresses))
	for _, group := range plan.Egresses {
		// direct keeps mark zero here: its traffic leaves by the uplink, which is
		// where an unmarked socket goes anyway.
		if group.ID != domain.EgressDirect {
			marks[group.ID] = group.Mark
		}
	}

	users := make([]domain.RealityUser, 0, len(state.Devices))
	for _, device := range state.Devices {
		uuid, err := domain.RealityUserUUID(privateKey, device.ID)
		if err != nil {
			return domain.RealityIngressSpec{}, fmt.Errorf("device %q: %w", device.ID, err)
		}
		users = append(users, domain.RealityUser{
			DeviceID: device.ID,
			UUID:     uuid,
			Mark:     marks[device.Egress],
		})
	}
	// Ordered so an unchanged revision renders byte-identically and the listener is
	// not restarted for a reshuffle.
	sort.Slice(users, func(i, j int) bool { return users[i].DeviceID < users[j].DeviceID })

	return domain.RealityIngressSpec{
		Enabled:    true,
		Port:       domain.RealityPort,
		ServerName: state.Hub.Fallback.Reality.ServerName,
		PrivateKey: privateKey,
		ShortID:    domain.RealityShortID(publicKey),
		DNSAddress: state.Hub.DNSAddress,
		Users:      users,
	}, nil
}
