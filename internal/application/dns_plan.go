package application

import (
	"fmt"
	"sort"

	"vpn-hub/internal/domain"
)

// DefaultPublicResolvers are used when the configuration names none. They are only
// ever queried from inside the default egress namespace, so the provider sees them
// rather than the hub.
var DefaultPublicResolvers = []string{"1.1.1.1", "9.9.9.9"}

// BuildDNSPlan derives the resolver policy from a revision.
//
// It needs the egress specs because the public resolver runs inside the namespace of
// whichever tunnel carries the internet, and that namespace's address is only known
// once the layout has been computed.
func BuildDNSPlan(state domain.DesiredState, plan domain.FirewallPlan, specs []domain.EgressSpec) (domain.DNSPlan, error) {
	if state.Hub.DNSAddress == "" {
		return domain.DNSPlan{}, fmt.Errorf("hub dns_address is required to serve DNS")
	}

	result := domain.DNSPlan{
		ListenAddress:   state.Hub.DNSAddress,
		ClientCIDR:      state.Hub.ClientCIDR,
		PublicResolvers: DefaultPublicResolvers,
	}

	for _, network := range plan.Internals {
		if len(network.Zones) == 0 {
			continue
		}
		if len(network.Resolvers) == 0 {
			// A zone with no resolver cannot be answered, and silently forwarding it
			// to a public server would send private names to the internet.
			return domain.DNSPlan{}, fmt.Errorf(
				"tunnel %q declares dns_zones but no dns_servers, so its names have nowhere to resolve",
				network.TunnelID)
		}
		for _, zone := range network.Zones {
			result.Zones = append(result.Zones, domain.DNSZoneRoute{
				Zone:      zone,
				Resolvers: network.Resolvers,
				Set:       "internal_" + safeIdentifier(network.TunnelID),
			})
		}
	}
	sort.Slice(result.Zones, func(i, j int) bool { return result.Zones[i].Zone < result.Zones[j].Zone })

	// Public queries follow whichever tunnel carries the internet for most devices.
	// With everyone on `direct` there is no namespace to hide in and the hub resolves
	// for itself, which is the honest outcome rather than a pretence of privacy.
	if egress := busiestEgress(state.Devices); egress != domain.EgressDirect && egress != "" {
		for _, spec := range specs {
			if spec.TunnelID == egress {
				result.UpstreamNamespace = spec.Namespace
				result.UpstreamAddress = hostOf(spec.PeerAddress)
				break
			}
		}
	}
	return result, nil
}

// busiestEgress picks the egress most devices use, so the resolver sits where most
// traffic already goes. Ties break by name to stay reproducible.
func busiestEgress(devices []domain.DeployedDevice) string {
	counts := map[string]int{}
	for _, device := range devices {
		counts[device.Egress]++
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)

	best, bestCount := "", 0
	for _, name := range names {
		if counts[name] > bestCount {
			best, bestCount = name, counts[name]
		}
	}
	return best
}

func safeIdentifier(value string) string {
	result := []rune(value)
	for index, symbol := range result {
		if symbol == '-' {
			result[index] = '_'
		}
	}
	return string(result)
}

func hostOf(address string) string {
	for index, symbol := range address {
		if symbol == '/' {
			return address[:index]
		}
	}
	return address
}
