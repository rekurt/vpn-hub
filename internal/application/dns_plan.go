package application

import (
	"fmt"
	"sort"

	"vpn-hub/internal/domain"
)

// DefaultPublicResolvers are queried from the device's selected egress.
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

	result := domain.DNSPlan{ClientCIDR: state.Hub.ClientCIDR}

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
		forwardAddress, namespace := privateResolverPlacement(network.TunnelID, specs)
		if forwardAddress != "" {
			result.PrivateResolvers = append(result.PrivateResolvers, domain.DNSPrivateResolver{
				TunnelID:  network.TunnelID,
				Namespace: namespace,
				Address:   forwardAddress,
				Resolvers: append([]string(nil), network.Resolvers...),
			})
		}
		for _, zone := range network.Zones {
			result.Zones = append(result.Zones, domain.DNSZoneRoute{
				Zone:           zone,
				Resolvers:      network.Resolvers,
				ForwardAddress: forwardAddress,
				Set:            "internal_" + safeIdentifier(network.TunnelID),
			})
		}
	}
	sort.Slice(result.Zones, func(i, j int) bool { return result.Zones[i].Zone < result.Zones[j].Zone })
	sort.Slice(result.PrivateResolvers, func(i, j int) bool { return result.PrivateResolvers[i].TunnelID < result.PrivateResolvers[j].TunnelID })

	specByID := make(map[string]domain.EgressSpec, len(specs))
	for _, spec := range specs {
		if _, exists := specByID[spec.TunnelID]; !exists {
			specByID[spec.TunnelID] = spec
		}
	}
	for _, group := range plan.Egresses {
		if len(group.Addresses) == 0 {
			continue
		}
		resolver := domain.DNSEgressResolver{
			EgressID:        group.ID,
			ClientAddresses: append([]string(nil), group.Addresses...),
			PublicResolvers: append([]string(nil), DefaultPublicResolvers...),
		}
		sort.Strings(resolver.ClientAddresses)
		if group.ID == domain.EgressDirect {
			resolver.HubAddress = state.Hub.DNSAddress
		} else {
			spec, known := specByID[group.ID]
			if !known {
				return domain.DNSPlan{}, fmt.Errorf("egress %q has assigned clients but no matching spec", group.ID)
			}
			resolver.HubAddress = hostOf(spec.HostAddress)
			resolver.Namespace = spec.Namespace
			resolver.NamespaceAddress = hostOf(spec.PeerAddress)
		}
		result.EgressResolvers = append(result.EgressResolvers, resolver)
	}
	sort.Slice(result.EgressResolvers, func(i, j int) bool {
		return result.EgressResolvers[i].EgressID < result.EgressResolvers[j].EgressID
	})
	return result, nil
}

func privateResolverPlacement(tunnelID string, specs []domain.EgressSpec) (address, namespace string) {
	for _, spec := range specs {
		if spec.TunnelID == tunnelID {
			return hostOf(spec.PeerAddress), spec.Namespace
		}
	}
	return "", ""
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
