// Package ports declares the interfaces the application layer drives.
//
// A port is added here when its adapter is written, not when it is first imagined:
// an interface with no implementation reads as a finished seam and hides how much of
// the system is still missing. Namespace, routing, DNS and per-protocol tunnel ports
// arrive with their adapters.
package ports

import (
	"context"
	"time"

	"vpn-hub/internal/domain"
)

type ConfigRepository interface {
	Load(context.Context) (domain.Config, error)
}

type RevisionStore interface {
	Save(context.Context, domain.DesiredState) error
	Load(context.Context) (domain.DesiredState, error)
}

// Firewall installs a rendered policy as a single transaction.
type Firewall interface {
	// Apply reports whether it replaced the live ruleset. The answer matters to the
	// resolver: replacement empties the sets it had been filling from DNS answers.
	Apply(context.Context, domain.FirewallPlan) (bool, error)
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

// RealityIngress runs the TCP/443 fallback listener. A spec with Enabled false
// asks for it to be gone, which is how turning the fallback off closes the port.
//
// It also reports what it is running, so a dry run says the same thing a real
// pass would do and a listener someone stopped shows up as drift.
type RealityIngress interface {
	Apply(context.Context, domain.RealityIngressSpec) error
	// Fingerprint is what Applied returns for a listener started from this spec.
	Fingerprint(domain.RealityIngressSpec) string
	// Applied reports the fingerprint the running listener was started from, and
	// the empty string when none is running -- a listener someone stopped is a
	// difference from the revision, not the absence of one.
	Applied(context.Context) (string, error)
}

// EgressManager runs upstream tunnels, each isolated in its own namespace.
type EgressManager interface {
	Apply(context.Context, []domain.EgressSpec) error
	Observe(context.Context) ([]string, error)
}

// TunnelConfigStore holds upstream provider configurations, which stay on the host
// rather than travelling inside a revision.
type TunnelConfigStore interface {
	Load(ctx context.Context, tunnel domain.Tunnel) (domain.Upstream, error)
}

// DNSManager installs the resolver policy: private zones into their tunnels,
// everything else through the default egress.
type DNSManager interface {
	// repopulate asks for the resolver to be replaced even when its configuration is
	// unchanged, so that the addresses it had learned are answered -- and added to
	// the packet filter's sets -- again.
	Apply(ctx context.Context, plan domain.DNSPlan, repopulate bool) error
}

// UpstreamWriter persists a tunnel's chosen upstream where the reconciler will find
// it, keeping the previous one as the fallback.
type UpstreamWriter interface {
	Write(ctx context.Context, tunnel domain.Tunnel, chosen domain.ProxyTunnel) error
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

// RevocationSource lists locally revoked device ids, consumed at deploy time so a
// revoked device never reaches the state the agent converges on.
type RevocationSource interface {
	Load(context.Context) ([]string, error)
}

// DeployConfirmation arms the deploy-and-confirm safety net and clears it.
type DeployConfirmation interface {
	// Arm reports false without error when there is no earlier revision to return
	// to -- the first deploy has nothing to roll back onto.
	Arm(ctx context.Context, within time.Duration, revision string) (armed bool, err error)
	Confirm() error
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
