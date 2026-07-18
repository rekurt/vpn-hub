package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
)

type Service struct {
	ConfigRepository    ports.ConfigRepository
	RevisionStore       ports.RevisionStore
	Reconciler          ports.Reconciler
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

func (s Service) BuildDesiredState(cfg domain.Config) (domain.DesiredState, error) {
	if err := Validate(cfg); err != nil {
		return domain.DesiredState{}, err
	}

	devices := append([]domain.Device(nil), cfg.Devices...)
	tunnels := append([]domain.Tunnel(nil), cfg.Tunnels...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })

	deployed := make([]domain.DeployedDevice, 0, len(devices))
	for _, device := range devices {
		profiles := append([]domain.DeviceProfile(nil), device.Profiles...)
		sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })

		result := domain.DeployedDevice{ID: device.ID, Profiles: make([]domain.DeployedProfile, 0, len(profiles))}
		for _, profile := range profiles {
			publicKey := profile.ClientPublicKey
			if profile.ClientPrivateKey != "" {
				derived, err := domain.PublicKeyFromPrivate(profile.ClientPrivateKey)
				if err != nil {
					return domain.DesiredState{}, fmt.Errorf("device %q profile %q: %w", device.ID, profile.ID, err)
				}
				if publicKey != "" && publicKey != derived {
					return domain.DesiredState{}, fmt.Errorf("device %q profile %q: public key does not match private key", device.ID, profile.ID)
				}
				publicKey = derived
			}
			result.Profiles = append(result.Profiles, domain.DeployedProfile{
				ID: profile.ID, Egress: profile.Egress, Address: profile.Address, ClientPublicKey: publicKey,
			})
		}
		deployed = append(deployed, result)
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

func (s Service) Plan(ctx context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	if s.Reconciler == nil {
		return nil, fmt.Errorf("reconciler is not configured")
	}
	return s.Reconciler.Plan(ctx, state)
}

func (s Service) Deploy(ctx context.Context, state domain.DesiredState, apply bool) ([]domain.Operation, error) {
	operations, err := s.Plan(ctx, state)
	if err != nil {
		return nil, err
	}
	if !apply {
		return operations, nil
	}
	if err := s.Reconciler.Apply(ctx, state); err != nil {
		return nil, err
	}
	if s.RevisionStore != nil {
		if err := s.RevisionStore.Save(ctx, state); err != nil {
			return nil, err
		}
	}
	return operations, nil
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

func (s Service) RenderProfile(cfg domain.Config, deviceID, egress string) (string, error) {
	if s.ProfileRenderer == nil {
		return "", fmt.Errorf("profile renderer is not configured")
	}
	for _, device := range cfg.Devices {
		if device.ID != deviceID {
			continue
		}
		for _, profile := range device.Profiles {
			if profile.Egress == egress {
				if profile.ClientPrivateKey == "" {
					return "", fmt.Errorf("profile %q has no local private key", profile.ID)
				}
				return s.ProfileRenderer.Render(cfg.Hub, profile)
			}
		}
		return "", fmt.Errorf("device %q has no egress profile %q", deviceID, egress)
	}
	return "", fmt.Errorf("device %q was not found", deviceID)
}

func Validate(cfg domain.Config) error {
	if cfg.Hub.Endpoint == "" || cfg.Hub.ServerPublicKey == "" || cfg.Hub.ClientCIDR == "" || cfg.Hub.DNSAddress == "" {
		return fmt.Errorf("hub.endpoint, hub.server_public_key, hub.client_cidr and hub.dns_address are required")
	}
	if err := validateHubNetwork(cfg.Hub); err != nil {
		return err
	}

	deviceIDs := make(map[string]struct{}, len(cfg.Devices))
	profileAddresses := make(map[string]string)
	for _, device := range cfg.Devices {
		if device.ID == "" {
			return fmt.Errorf("device id is required")
		}
		if _, exists := deviceIDs[device.ID]; exists {
			return fmt.Errorf("duplicate device %q", device.ID)
		}
		deviceIDs[device.ID] = struct{}{}
		profileIDs := make(map[string]struct{}, len(device.Profiles))
		for _, profile := range device.Profiles {
			if profile.ID == "" || profile.Egress == "" || profile.Address == "" {
				return fmt.Errorf("device %q: profile id, egress and address are required", device.ID)
			}
			if _, exists := profileIDs[profile.ID]; exists {
				return fmt.Errorf("device %q: duplicate profile %q", device.ID, profile.ID)
			}
			profileIDs[profile.ID] = struct{}{}
			if err := validateProfileAddress(profile.Address); err != nil {
				return fmt.Errorf("device %q profile %q: %w", device.ID, profile.ID, err)
			}
			if profile.ClientPrivateKey == "" && profile.ClientPublicKey == "" {
				return fmt.Errorf("device %q profile %q: a client public or private key is required", device.ID, profile.ID)
			}
			if previous, exists := profileAddresses[profile.Address]; exists {
				return fmt.Errorf("profile address %q is shared by %s and %s", profile.Address, previous, device.ID+"/"+profile.ID)
			}
			profileAddresses[profile.Address] = device.ID + "/" + profile.ID
		}
	}

	tunnelIDs := make(map[string]domain.Tunnel, len(cfg.Tunnels))
	zones := make(map[string]string)
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == "" {
			return fmt.Errorf("tunnel id is required")
		}
		if _, exists := tunnelIDs[tunnel.ID]; exists {
			return fmt.Errorf("duplicate tunnel %q", tunnel.ID)
		}
		if err := validateTunnel(tunnel, deviceIDs); err != nil {
			return err
		}
		tunnelIDs[tunnel.ID] = tunnel
		for _, rawZone := range tunnel.DNSZones {
			zone := normalizeZone(rawZone)
			if zone == "" {
				return fmt.Errorf("tunnel %q: empty DNS zone", tunnel.ID)
			}
			for existing, existingTunnel := range zones {
				if zonesOverlap(zone, existing) {
					return fmt.Errorf("DNS zone %q in tunnel %q conflicts with %q in tunnel %q", zone, tunnel.ID, existing, existingTunnel)
				}
			}
			zones[zone] = tunnel.ID
		}
	}

	for _, device := range cfg.Devices {
		for _, profile := range device.Profiles {
			if profile.Egress == "direct" {
				continue
			}
			tunnel, exists := tunnelIDs[profile.Egress]
			if !exists || tunnel.Role != domain.RoleEgress {
				return fmt.Errorf("device %q profile %q: egress %q is not an egress tunnel", device.ID, profile.ID, profile.Egress)
			}
			if len(tunnel.AllowedDevices) > 0 && !contains(tunnel.AllowedDevices, device.ID) {
				return fmt.Errorf("device %q profile %q is not allowed to use egress %q", device.ID, profile.ID, profile.Egress)
			}
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
		if tunnel.Source.Kind != domain.SourceXrayURI && tunnel.Source.Kind != domain.SourceXrayJSON && tunnel.Source.Kind != domain.SourceSubscription {
			return fmt.Errorf("tunnel %q: Xray source must be xray-uri, xray-json or subscription", tunnel.ID)
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
