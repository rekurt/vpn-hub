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
	// Observe returns the fingerprint carried by the live ruleset, empty when there
	// is none.
	Observe(context.Context) (string, error)
	// Fingerprint is what Observe would return for a plan that is correctly loaded.
	Fingerprint(domain.FirewallPlan) string
}

// Ingress manages the interface clients connect to.
type Ingress interface {
	Apply(context.Context, domain.IngressSpec) error
	Observe(ctx context.Context, name string) (domain.IngressObservation, error)
}

// EgressManager runs upstream tunnels, each isolated in its own namespace.
type EgressManager interface {
	Apply(context.Context, []domain.EgressSpec) error
	Observe(context.Context) ([]string, error)
}

// TunnelConfigStore holds upstream provider configurations, which stay on the host
// rather than travelling inside a revision.
type TunnelConfigStore interface {
	Load(ctx context.Context, source string) (domain.WireGuardTunnel, error)
}

// DNSManager installs the resolver policy: private zones into their tunnels,
// everything else through the default egress.
type DNSManager interface {
	Apply(context.Context, domain.DNSPlan) error
}

// HostNetwork answers questions about the machine the hub runs on, which cannot come
// from configuration.
type HostNetwork interface {
	UplinkInterface(context.Context) (string, error)
}

// ServerKeyStore holds the hub's own private key. It stays on the host and is never
// carried in a revision.
type ServerKeyStore interface {
	PrivateKey(context.Context) (string, error)
}

// Reconciler converges a host towards a revision. Apply returns the differences it
// closed, so a caller can report drift without asking twice.
type Reconciler interface {
	Observe(context.Context) (domain.ObservedState, error)
	Plan(context.Context, domain.DesiredState) ([]domain.Operation, error)
	Apply(context.Context, domain.DesiredState) ([]domain.Operation, error)
}

type HealthChecker interface {
	Check(context.Context, domain.Tunnel) (domain.TunnelHealth, error)
}

type SubscriptionFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

// ProfileRenderer builds a client configuration. It is given the private key rather
// than a stored profile, because the hub keeps only public keys.
type ProfileRenderer interface {
	Render(hub domain.Hub, address, privateKey string) (string, error)
}
