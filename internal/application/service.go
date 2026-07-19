package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
)

type Service struct {
	ConfigRepository    ports.ConfigRepository
	RevisionStore       ports.RevisionStore
	HealthChecker       ports.HealthChecker
	SubscriptionFetcher ports.SubscriptionFetcher
	ProfileRenderer     ports.ProfileRenderer
	Now                 func() time.Time
}

func (s Service) LoadAndValidate(ctx context.Context) (domain.Config, error) {
	if s.ConfigRepository == nil {
		return domain.Config{}, fmt.Errorf("config repository is not configured")
	}
	cfg, err := s.ConfigRepository.Load(ctx)
	if err != nil {
		return domain.Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return domain.Config{}, err
	}
	return cfg, nil
}

// BuildDesiredState compiles a configuration into the immutable revision the agent
// converges on.
//
// The configuration must already have passed Validate; LoadAndValidate does that on
// every path that reaches here. Re-validating would also reject a configuration that
// RemoveRevoked has legitimately pruned, since egress ACLs keep naming devices that
// are deliberately gone.
func (s Service) BuildDesiredState(cfg domain.Config) (domain.DesiredState, error) {
	devices := append([]domain.Device(nil), cfg.Devices...)
	tunnels := append([]domain.Tunnel(nil), cfg.Tunnels...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })

	// Disabled tunnels are dropped here rather than filtered downstream: the revision
	// is what the agent converges on, so a tunnel that survives into it would still
	// get a namespace and a route.
	enabled := make([]domain.Tunnel, 0, len(tunnels))
	for _, tunnel := range tunnels {
		if tunnel.IsEnabled() {
			enabled = append(enabled, tunnel)
		}
	}
	tunnels = enabled

	deployed := make([]domain.DeployedDevice, 0, len(devices))
	for _, device := range devices {
		deployed = append(deployed, domain.DeployedDevice{
			ID: device.ID, Address: device.Address,
			PublicKey: device.PublicKey, Egress: device.Egress,
		})
	}

	state := domain.DesiredState{Hub: cfg.Hub, Devices: deployed, Tunnels: tunnels}
	payload, err := json.Marshal(state)
	if err != nil {
		return domain.DesiredState{}, fmt.Errorf("marshal desired state: %w", err)
	}
	digest := sha256.Sum256(payload)
	state.Revision = hex.EncodeToString(digest[:])[:16]
	if s.Now == nil {
		s.Now = time.Now
	}
	state.GeneratedAt = s.Now().UTC()
	return state, nil
}

// Save persists a compiled revision. Converging the host onto it is the agent's job,
// so nothing here touches the machine: hubctl usually runs on a workstation that has
// no hub to configure.
func (s Service) Save(ctx context.Context, state domain.DesiredState) error {
	if s.RevisionStore == nil {
		return fmt.Errorf("revision store is not configured")
	}
	return s.RevisionStore.Save(ctx, state)
}

func (s Service) TestTunnel(ctx context.Context, cfg domain.Config, id string) (domain.TunnelHealth, error) {
	if s.HealthChecker == nil {
		return domain.TunnelHealth{}, fmt.Errorf("health checker is not configured")
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == id {
			return s.HealthChecker.Check(ctx, tunnel)
		}
	}
	return domain.TunnelHealth{}, fmt.Errorf("tunnel %q was not found", id)
}

func (s Service) RefreshSubscription(ctx context.Context, cfg domain.Config, id string) ([]byte, error) {
	if s.SubscriptionFetcher == nil {
		return nil, fmt.Errorf("subscription fetcher is not configured")
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID != id {
			continue
		}
		if tunnel.Type != domain.TunnelXray || tunnel.Source.Kind != domain.SourceSubscription {
			return nil, fmt.Errorf("tunnel %q is not an Xray subscription", id)
		}
		return s.SubscriptionFetcher.Fetch(ctx, tunnel.Source.Value)
	}
	return nil, fmt.Errorf("tunnel %q was not found", id)
}

func Validate(cfg domain.Config) error {
	if cfg.Hub.Endpoint == "" || cfg.Hub.ServerPublicKey == "" || cfg.Hub.ClientCIDR == "" || cfg.Hub.DNSAddress == "" {
		return fmt.Errorf("hub.endpoint, hub.server_public_key, hub.client_cidr and hub.dns_address are required")
	}
	if err := validateHubNetwork(cfg.Hub); err != nil {
		return err
	}

	deviceIDs := make(map[string]struct{}, len(cfg.Devices))
	addresses := make(map[string]string)
	for _, device := range cfg.Devices {
		if device.ID == "" {
			return fmt.Errorf("device id is required")
		}
		if err := validateIdentifier("device id", device.ID); err != nil {
			return err
		}
		// Profiles existed to pick an egress per connection; the hub now decides by
		// destination, so saying what replaced them beats "unknown field".
		if len(device.Profiles) > 0 {
			return fmt.Errorf("device %q still uses `profiles`, which no longer exists: "+
				"give the device one `address`, one `public_key` and one `egress` "+
				"naming its default internet path; private networks are reached in "+
				"addition to it and are not listed per device", device.ID)
		}
		if _, exists := deviceIDs[device.ID]; exists {
			return fmt.Errorf("duplicate device %q", device.ID)
		}
		deviceIDs[device.ID] = struct{}{}

		if device.Address == "" || device.PublicKey == "" || device.Egress == "" {
			return fmt.Errorf("device %q: address, public_key and egress are required", device.ID)
		}
		if err := validateProfileAddress(device.Address, cfg.Hub.ClientCIDR); err != nil {
			return fmt.Errorf("device %q: %w", device.ID, err)
		}
		if err := domain.ValidatePublicKey(device.PublicKey); err != nil {
			return fmt.Errorf("device %q: %w", device.ID, err)
		}
		if previous, exists := addresses[device.Address]; exists {
			return fmt.Errorf("address %q is shared by %s and %s", device.Address, previous, device.ID)
		}
		addresses[device.Address] = device.ID
	}

	tunnelIDs := make(map[string]domain.Tunnel, len(cfg.Tunnels))
	zones := make(map[string]string)
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == "" {
			return fmt.Errorf("tunnel id is required")
		}
		if err := validateIdentifier("tunnel id", tunnel.ID); err != nil {
			return err
		}
		if len(tunnel.ID) > maxTunnelIDLength {
			return fmt.Errorf("tunnel id %q is %d characters; at most %d fit in an interface name", tunnel.ID, len(tunnel.ID), maxTunnelIDLength)
		}
		if _, exists := tunnelIDs[tunnel.ID]; exists {
			return fmt.Errorf("duplicate tunnel %q", tunnel.ID)
		}
		if err := validateTunnel(tunnel, deviceIDs); err != nil {
			return err
		}
		if err := tunnel.Health.Validate(); err != nil {
			return fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
		}
		tunnelIDs[tunnel.ID] = tunnel
		// Caught here rather than on the host: a zone with no resolver cannot be
		// answered, and the reconcile that discovers it does so on every tick.
		if len(tunnel.DNSZones) > 0 && len(tunnel.DNSServers) == 0 {
			return fmt.Errorf(
				"tunnel %q declares dns_zones but no dns_servers, so its names have nowhere to resolve",
				tunnel.ID)
		}
		for _, resolver := range tunnel.DNSServers {
			if _, err := netip.ParseAddr(resolver); err != nil {
				return fmt.Errorf("tunnel %q: dns_servers entry %q is not an IP address", tunnel.ID, resolver)
			}
		}
		for _, rawZone := range tunnel.DNSZones {
			zone := normalizeZone(rawZone)
			if zone == "" {
				return fmt.Errorf("tunnel %q: empty DNS zone", tunnel.ID)
			}
			// A zone becomes a line in the resolver's configuration file, so a value
			// carrying a newline would write a directive of its own -- `address=/#/`
			// alone is enough to point every client's every lookup wherever the
			// author of that string chose.
			if err := domain.ValidateDNSZone(zone); err != nil {
				return fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
			}
			for existing, existingTunnel := range zones {
				if zonesOverlap(zone, existing) {
					return fmt.Errorf("DNS zone %q in tunnel %q conflicts with %q in tunnel %q", zone, tunnel.ID, existing, existingTunnel)
				}
			}
			zones[zone] = tunnel.ID
		}
	}

	enabledEgresses := 0
	for _, tunnel := range cfg.Tunnels {
		if tunnel.Role == domain.RoleEgress && tunnel.IsEnabled() {
			enabledEgresses++
		}
	}

	for _, device := range cfg.Devices {
		if device.Egress == domain.EgressDirect {
			continue
		}
		tunnel, exists := tunnelIDs[device.Egress]
		if !exists || tunnel.Role != domain.RoleEgress {
			return fmt.Errorf("device %q: egress %q is not an egress tunnel", device.ID, device.Egress)
		}
		// Disabling a tunnel someone depends on must fail here rather than leave that
		// device without internet, and it must not fall back to direct: a silent
		// fallback is exactly what the kill switch exists to prevent.
		if !tunnel.IsEnabled() {
			return fmt.Errorf("device %q uses egress %q, which is disabled: "+
				"move the device with `hubctl device set-egress` before disabling it", device.ID, device.Egress)
		}
		if len(tunnel.AllowedDevices) > 0 && !contains(tunnel.AllowedDevices, device.ID) {
			return fmt.Errorf("device %q is not allowed to use egress %q", device.ID, device.Egress)
		}
	}

	if len(cfg.Devices) > 0 && enabledEgresses == 0 {
		hasDirect := false
		for _, device := range cfg.Devices {
			if device.Egress == domain.EgressDirect {
				hasDirect = true
			}
		}
		if !hasDirect {
			return fmt.Errorf("no egress tunnel is enabled, so no device has a way out")
		}
	}

	return validateRouteOverlaps(cfg.Tunnels)
}

func validateTunnel(tunnel domain.Tunnel, deviceIDs map[string]struct{}) error {
	if tunnel.Type != domain.TunnelWireGuard && tunnel.Type != domain.TunnelOpenVPN && tunnel.Type != domain.TunnelXray && tunnel.Type != domain.TunnelAmneziaWG {
		return fmt.Errorf("tunnel %q: unsupported type %q", tunnel.ID, tunnel.Type)
	}
	if tunnel.Role != domain.RolePrivateNetwork && tunnel.Role != domain.RoleEgress {
		return fmt.Errorf("tunnel %q: unsupported role %q", tunnel.ID, tunnel.Role)
	}
	if tunnel.Source.Value == "" {
		return fmt.Errorf("tunnel %q: source value is required", tunnel.ID)
	}
	if tunnel.Type == domain.TunnelXray {
		switch tunnel.Source.Kind {
		case domain.SourceConfig, domain.SourceSubscription:
		case domain.SourceXrayURI, domain.SourceXrayJSON:
			// An inline link carries a UUID, and a revision is written to disk. The
			// link belongs in a file the host holds, named by the revision.
			return fmt.Errorf("tunnel %q: put the link in a file and use `kind: config`; "+
				"an inline %s would carry its credential into every saved revision",
				tunnel.ID, tunnel.Source.Kind)
		default:
			return fmt.Errorf("tunnel %q: an Xray source must be config or subscription", tunnel.ID)
		}
	} else if tunnel.Source.Kind != domain.SourceConfig {
		return fmt.Errorf("tunnel %q: %s source must use kind config", tunnel.ID, tunnel.Type)
	}
	for _, deviceID := range tunnel.AllowedDevices {
		if _, exists := deviceIDs[deviceID]; !exists {
			return fmt.Errorf("tunnel %q: allowed device %q does not exist", tunnel.ID, deviceID)
		}
	}
	return nil
}

func validateRouteOverlaps(tunnels []domain.Tunnel) error {
	type routeOwner struct{ tunnel, route string }
	var routes []routeOwner
	for _, tunnel := range tunnels {
		for _, route := range tunnel.Routes {
			if _, err := parseNetworkPrefix(route); err != nil {
				return fmt.Errorf("tunnel %q: invalid route %q: %w", tunnel.ID, route, err)
			}
			for _, seen := range routes {
				if prefixesOverlap(route, seen.route) {
					return fmt.Errorf("route %q in tunnel %q conflicts with %q in tunnel %q", route, tunnel.ID, seen.route, seen.tunnel)
				}
			}
			routes = append(routes, routeOwner{tunnel.ID, route})
		}
	}
	return nil
}

func normalizeZone(zone string) string { return strings.Trim(strings.ToLower(zone), ". ") }

func zonesOverlap(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
