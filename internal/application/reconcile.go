package application

import (
	"context"
	"fmt"
	"time"

	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
)

// HostReconciler applies a desired state to the machine.
//
// The orchestration lives here rather than in an adapter so that deciding what the
// host should look like stays testable without a host: the adapters it drives only
// format and execute.
type HostReconciler struct {
	Firewall      ports.Firewall
	Ingress       ports.Ingress
	Egress        ports.EgressManager
	DNS           ports.DNSManager
	TunnelConfigs ports.TunnelConfigStore
	Host          ports.HostNetwork
	ServerKey     ports.ServerKeyStore
	Now           func() time.Time
}

// Observe reads back what the host currently looks like. Without this step the agent
// cannot tell convergence from repetition, and drift is invisible.
func (r HostReconciler) Observe(ctx context.Context) (domain.ObservedState, error) {
	if r.Firewall == nil || r.Ingress == nil {
		return domain.ObservedState{}, fmt.Errorf("host reconciler is not fully configured")
	}

	now := r.Now
	if now == nil {
		now = time.Now
	}
	state := domain.ObservedState{ObservedAt: now().UTC()}

	revision, err := r.Firewall.Observe(ctx)
	if err != nil {
		return domain.ObservedState{}, fmt.Errorf("observe firewall: %w", err)
	}
	state.FirewallRevision = revision

	ingress, err := r.Ingress.Observe(ctx, IngressInterface)
	if err != nil {
		return domain.ObservedState{}, fmt.Errorf("observe ingress: %w", err)
	}
	state.Ingress = ingress
	return state, nil
}

// Plan reports what differs between the revision and the host, without changing
// anything.
func (r HostReconciler) Plan(ctx context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	compiled, err := r.compile(ctx, state)
	if err != nil {
		return nil, err
	}
	observed, err := r.Observe(ctx)
	if err != nil {
		return nil, err
	}
	return Diff(compiled.ingress, r.Firewall.Fingerprint(compiled.firewall), observed), nil
}

// Apply converges the host and returns the differences it closed.
//
// It applies unconditionally rather than only when the diff is non-empty. The
// adapters are idempotent and cheap, and applying regardless is what makes any
// tampering -- including edits the fingerprint cannot see, such as a single rule
// changed in place -- disappear on the next tick. The diff decides what is worth
// reporting, not whether to converge.
func (r HostReconciler) Apply(ctx context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	compiled, err := r.compile(ctx, state)
	if err != nil {
		return nil, err
	}
	plan, spec, egresses := compiled.firewall, compiled.ingress, compiled.egresses

	observed, err := r.Observe(ctx)
	if err != nil {
		return nil, err
	}
	operations := Diff(spec, r.Firewall.Fingerprint(plan), observed)

	// The packet filter goes in first. Doing it the other way round would leave a
	// window where the ingress interface is up and forwarding under whatever rules
	// happened to be loaded.
	rebuilt, err := r.Firewall.Apply(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("apply firewall: %w", err)
	}
	if err := r.Ingress.Apply(ctx, spec); err != nil {
		return nil, fmt.Errorf("apply ingress: %w", err)
	}
	// Egress namespaces come last: the marks that steer traffic into them are already
	// installed, so a half-built namespace drops traffic rather than leaking it.
	if r.Egress != nil {
		if err := r.Egress.Apply(ctx, egresses); err != nil {
			return nil, fmt.Errorf("apply egress: %w", err)
		}
	}
	// Resolvers after the namespaces they live in and forward through. The plan
	// itself was derived by compile, before any of the above ran.
	if r.DNS != nil {
		if err := r.DNS.Apply(ctx, compiled.dns, rebuilt); err != nil {
			return nil, fmt.Errorf("apply dns: %w", err)
		}
	}
	return operations, nil
}

// socksEndpoints exposes each tunnel namespace as a proxy on the hub's end of its
// link. A laptop can then send one application through a chosen provider without
// moving its whole connection.
func socksEndpoints(specs []domain.EgressSpec, plan domain.FirewallPlan) []domain.SocksEndpoint {
	// The devices allowed to reach a tunnel are already worked out for the egress
	// groups and the private networks; an endpoint answers to the same list.
	permitted := make(map[string][]string, len(plan.Egresses)+len(plan.Internals))
	for _, group := range plan.Egresses {
		permitted[group.ID] = group.Clients
	}
	for _, network := range plan.Internals {
		permitted[network.TunnelID] = network.Clients
	}

	endpoints := make([]domain.SocksEndpoint, 0, len(specs))
	for _, spec := range specs {
		if spec.SocksPort == 0 {
			continue
		}
		endpoints = append(endpoints, domain.SocksEndpoint{
			TunnelID:  spec.TunnelID,
			Address:   hostOf(spec.HostAddress),
			Interface: spec.HostVeth,
			Port:      spec.SocksPort,
			Clients:   permitted[spec.TunnelID],
		})
	}
	return endpoints
}

// compiled holds everything a revision turns into before any of it is applied.
type compiled struct {
	firewall domain.FirewallPlan
	ingress  domain.IngressSpec
	egresses []domain.EgressSpec
	dns      domain.DNSPlan
}

// compile turns a revision into the artefacts the host needs. All of them are
// derived before anything is applied, so a configuration error fails before the
// machine has been touched -- and `reconcile --dry-run` sees the same errors a real
// pass would. The DNS plan used to be built after the packet filter, the ingress and
// the namespaces were already in place, so a revision declaring dns_zones with no
// dns_servers passed validation, reported cleanly in a dry run, and then failed on
// every tick with the host half-configured and no resolver at all.
func (r HostReconciler) compile(ctx context.Context, state domain.DesiredState) (compiled, error) {
	if r.Firewall == nil || r.Ingress == nil || r.Host == nil || r.ServerKey == nil {
		return compiled{}, fmt.Errorf("host reconciler is not fully configured")
	}

	uplink, err := r.Host.UplinkInterface(ctx)
	if err != nil {
		return compiled{}, fmt.Errorf("find uplink interface: %w", err)
	}
	plan, err := BuildFirewallPlan(state, uplink)
	if err != nil {
		return compiled{}, err
	}

	privateKey, err := r.ServerKey.PrivateKey(ctx)
	if err != nil {
		return compiled{}, err
	}
	spec, err := BuildIngressSpec(state, privateKey)
	if err != nil {
		return compiled{}, err
	}

	egresses, err := r.compileEgresses(ctx, state, plan)
	if err != nil {
		return compiled{}, err
	}

	// Completed before the fingerprint is taken anywhere: a plan fingerprinted in one
	// shape and rendered in another reports drift against itself forever.
	plan.Socks = socksEndpoints(egresses, plan)

	dns, err := BuildDNSPlan(state, plan, egresses)
	if err != nil {
		return compiled{}, err
	}
	return compiled{firewall: plan, ingress: spec, egresses: egresses, dns: dns}, nil
}

// compileEgresses loads each upstream configuration and derives its namespace. The
// configurations are read before anything is applied, so a missing or malformed
// provider file fails the reconcile rather than leaving half the tunnels up.
func (r HostReconciler) compileEgresses(ctx context.Context, state domain.DesiredState, plan domain.FirewallPlan) ([]domain.EgressSpec, error) {
	if r.Egress == nil || r.TunnelConfigs == nil {
		return nil, nil
	}

	// Private networks need their upstream configuration just as egresses do: they
	// are tunnels the hub dials, only reached by destination rather than chosen.
	needed := make(map[string]struct{})
	for _, placement := range placements(plan) {
		needed[placement.id] = struct{}{}
	}
	if len(needed) == 0 {
		return nil, nil
	}

	tunnels := make(map[string]domain.Upstream, len(needed))
	for _, tunnel := range state.Tunnels {
		if _, wanted := needed[tunnel.ID]; !wanted {
			continue
		}
		upstream, err := r.TunnelConfigs.Load(ctx, tunnel)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
		}
		tunnels[tunnel.ID] = upstream
	}
	return BuildEgressSpecs(state, plan, tunnels)
}
