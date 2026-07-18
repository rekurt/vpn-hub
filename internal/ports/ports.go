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

type NamespaceManager interface {
	Ensure(context.Context, string) error
	Delete(context.Context, string) error
}

type NetAdmin interface {
	EnsureVeth(context.Context, string, string) error
	EnsurePolicyRoute(context.Context, string, uint32) error
}

type Firewall interface {
	Apply(context.Context, domain.DesiredState) error
}

type DNSManager interface {
	Apply(context.Context, domain.DesiredState) error
}

type TunnelDriver interface {
	Type() domain.TunnelType
	Apply(context.Context, domain.Tunnel) error
	Status(context.Context, domain.Tunnel) (domain.TunnelHealth, error)
}

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
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
