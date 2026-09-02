package application

import (
	"context"
	"errors"
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
	// Reality and RealityKey drive the optional TCP/443 fallback. Both nil means
	// the hub simply has no fallback listener to manage.
	Reality    ports.RealityIngress
	RealityKey ports.ServerKeyStore
	Now        func() time.Time
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

	// The fallback listener, when the hub has one to manage. Without this it was
	// the one component nothing observed: a dry run reported a clean host while a
	// real pass would restart it, and a listener someone stopped was never
	// mentioned as drift.
	if r.Reality != nil {
		fingerprint, err := r.Reality.Applied(ctx)
		if err != nil {
			return domain.ObservedState{}, fmt.Errorf("observe reality fallback: %w", err)
		}
		state.RealityFingerprint = fingerprint
	}
	return state, nil
}

// Plan reports what differs between the revision and the host, without changing
// anything.
func (r HostReconciler) Plan(ctx context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	compiled, err := r.compile(ctx, state)
	if err != nil {
		return nil, err
	}
	// Reported here as well as in Apply, and for the same reason compile derives
	// everything up front: a dry run must see the errors a real pass would. A
	// fallback whose key is missing is deliberately not fatal, but a `reconcile
	// --dry-run` that answered "nothing to do" would hide a failure repeating on
	// every tick with TCP/443 staying shut.
	if compiled.realityErr != nil {
		return nil, fmt.Errorf("compile reality fallback: %w", compiled.realityErr)
	}
	observed, err := r.Observe(ctx)
	if err != nil {
		return nil, err
	}
	return Diff(compiled.ingress, r.Firewall.Fingerprint(compiled.firewall),
		r.realityFingerprint(compiled.reality), observed), nil
}

// realityFingerprint is what a listener running this spec would report, and the
// empty string on a hub with no fallback configured at all -- which is what an
// unobserved listener reports too, so the two agree and nothing is reported.
func (r HostReconciler) realityFingerprint(spec domain.RealityIngressSpec) string {
	if r.Reality == nil {
		return ""
	}
	return r.Reality.Fingerprint(spec)
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
	operations := Diff(spec, r.Firewall.Fingerprint(plan), r.realityFingerprint(compiled.reality), observed)

	// The packet filter goes in first. Doing it the other way round would leave a
	// window where the ingress interface is up and forwarding under whatever rules
	// happened to be loaded.
	repopulate, firewallErr := r.Firewall.Apply(ctx, plan)
	if firewallErr != nil && !repopulate {
		return nil, fmt.Errorf("apply firewall: %w", firewallErr)
	}
	var errs []error
	if firewallErr != nil {
		errs = append(errs, fmt.Errorf("apply firewall: %w", firewallErr))
	}
	if err := r.Ingress.Apply(ctx, spec); err != nil {
		if !repopulate {
			return nil, fmt.Errorf("apply ingress: %w", err)
		}
		errs = append(errs, fmt.Errorf("apply ingress: %w", err))
	}
	// Egress namespaces come last: the marks that steer traffic into them are already
	// installed, so a half-built namespace drops traffic rather than leaking it.
	//
	// A failing egress -- an OpenVPN or Xray provider that is down -- must NOT stop
	// the DNS layer from converging. Egress.Apply already isolates its per-tunnel
	// failures, but its non-nil result used to short-circuit the reconcile before
	// DNS.Apply ran. On a tick that rebuilt the firewall the internal sets were just
	// emptied, so skipping DNS left private-zone answers unpopulated and their traffic
	// following the default (internet) egress -- the silent misroute the rebuild
	// exists to prevent. So apply DNS regardless and report both errors together.
	if r.Egress != nil {
		if err := r.Egress.Apply(ctx, egresses); err != nil {
			errs = append(errs, fmt.Errorf("apply egress: %w", err))
		}
	}
	// Resolvers after the namespaces they live in and forward through. The plan
	// itself was derived by compile, before any of the above ran.
	if r.DNS != nil {
		dnsErr := r.DNS.Apply(ctx, compiled.dns, repopulate)
		if dnsErr != nil {
			errs = append(errs, fmt.Errorf("apply dns: %w", dnsErr))
		} else if repopulate && firewallErr == nil {
			if err := r.Firewall.CommitDNSRepopulation(ctx, plan); err != nil {
				errs = append(errs, fmt.Errorf("commit DNS repopulation: %w", err))
			}
		}
	}
	// The fallback listener is the last thing and its failure is collected rather
	// than returned: it is an alternative way in, so a hub whose listener will not
	// start must still converge everything the ordinary ingress depends on.
	if compiled.realityErr != nil {
		errs = append(errs, fmt.Errorf("compile reality fallback: %w", compiled.realityErr))
	}
	if r.Reality != nil {
		if err := r.Reality.Apply(ctx, compiled.reality); err != nil {
			errs = append(errs, fmt.Errorf("apply reality fallback: %w", err))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
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
	reality  domain.RealityIngressSpec
	// realityErr records a fallback that could not be compiled -- almost always a
	// missing key. It is carried rather than returned so the rest of the revision
	// still converges; Apply reports it alongside any other partial failure.
	realityErr error
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

	// Settled before the plan is built, because a fallback that cannot run must not
	// leave 443 accepted with nothing behind it. Turning the fallback on without
	// generating its key used to fail the whole compile, which stopped the agent
	// converging the firewall, the ingress, the tunnels and DNS -- every tick,
	// until someone noticed. An alternative way in is not worth the hub.
	realityKey, realityErr := r.realityKey(ctx, state)
	if realityErr != nil {
		state.Hub.Fallback.Reality.Enabled = false
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

	reality, err := BuildRealityIngressSpec(state, plan, realityKey)
	if err != nil {
		// Same reasoning as the key: a fallback that will not compile is reported,
		// not allowed to hold up everything else.
		reality, realityErr = domain.RealityIngressSpec{}, err
	}
	return compiled{
		firewall: plan, ingress: spec, egresses: egresses, dns: dns,
		reality: reality, realityErr: realityErr,
	}, nil
}

// realityKey reads the fallback key, and only when the fallback is on: a hub that
// does not use it never needs the key to exist.
func (r HostReconciler) realityKey(ctx context.Context, state domain.DesiredState) (string, error) {
	if r.Reality == nil || !state.Hub.Fallback.Reality.Enabled {
		return "", nil
	}
	if r.RealityKey == nil {
		return "", fmt.Errorf("the REALITY fallback is enabled but no key store is configured")
	}
	return r.RealityKey.PrivateKey(ctx)
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
