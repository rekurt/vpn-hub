// Package ports declares the interfaces the application layer drives.
//
// A port is added here when its adapter is written, not when it is first imagined:
// an interface with no implementation reads as a finished seam and hides how much of
// the system is still missing. Namespace, routing, DNS and per-protocol tunnel ports
// arrive with their adapters.
package ports

import (
	"context"

	"vpn-hub/internal/domain"
)

type ConfigRepository interface {
	Load(context.Context) (domain.Config, error)
}

type RevisionStore interface {
	Save(context.Context, domain.DesiredState) error
	Load(context.Context) (domain.DesiredState, error)
}

type SecretStore interface {
	Decrypt(context.Context, string) ([]byte, error)
}

// Firewall installs a rendered policy as a single transaction.
type Firewall interface {
	Apply(context.Context, domain.FirewallPlan) error
}

type Reconciler interface {
	Plan(context.Context, domain.DesiredState) ([]domain.Operation, error)
	Apply(context.Context, domain.DesiredState) error
}

type HealthChecker interface {
	Check(context.Context, domain.Tunnel) (domain.TunnelHealth, error)
}

type SubscriptionFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

type ProfileRenderer interface {
	Render(domain.Hub, domain.DeviceProfile) (string, error)
}
