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
		// direct is marked too, although its traffic leaves by the uplink either
		// way. The mark is what tells the packet filter's output_mark chain that
		// this connection has already chosen its way out: an unmarked one would be
		// re-marked by destination into a private network's tunnel, which is how a
		// device excluded from that network by allowed_devices could still reach it.
		marks[group.ID] = group.Mark
	}

	users := make([]domain.RealityUser, 0, len(state.Devices))
	for _, device := range state.Devices {
		uuid, err := domain.RealityUserUUID(privateKey, device.ID, device.PublicKey)
		if err != nil {
			return domain.RealityIngressSpec{}, fmt.Errorf("device %q: %w", device.ID, err)
		}
		// Asked rather than taken, because the zero value is a working mark: it means
		// "unmarked", and an unmarked connection leaves by the uplink and is re-marked
		// by destination. So a plan that does not name this device's egress would not
		// fail here -- it would quietly hand the device the ordinary way out instead
		// of the tunnel it chose, and let it into private networks its allowed_devices
		// excludes it from. The plan is built from this same state, so this cannot
		// happen today; it is guarded because nothing about the types says so, and
		// because the way it would fail is silent.
		mark, planned := marks[device.Egress]
		if !planned {
			return domain.RealityIngressSpec{}, fmt.Errorf(
				"device %q leaves through %q, which the firewall plan does not know",
				device.ID, device.Egress)
		}
		users = append(users, domain.RealityUser{
			DeviceID: device.ID,
			UUID:     uuid,
			Mark:     mark,
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
