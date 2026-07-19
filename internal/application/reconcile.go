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
	Firewall  ports.Firewall
	Ingress   ports.Ingress
	Host      ports.HostNetwork
	ServerKey ports.ServerKeyStore
	Now       func() time.Time
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
	plan, spec, err := r.compile(ctx, state)
	if err != nil {
		return nil, err
	}
	observed, err := r.Observe(ctx)
	if err != nil {
		return nil, err
	}
	return Diff(spec, r.Firewall.Fingerprint(plan), observed), nil
}

// Apply converges the host and returns the differences it closed.
//
// It applies unconditionally rather than only when the diff is non-empty. The
// adapters are idempotent and cheap, and applying regardless is what makes any
// tampering -- including edits the fingerprint cannot see, such as a single rule
// changed in place -- disappear on the next tick. The diff decides what is worth
// reporting, not whether to converge.
func (r HostReconciler) Apply(ctx context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	plan, spec, err := r.compile(ctx, state)
	if err != nil {
		return nil, err
	}

	observed, err := r.Observe(ctx)
	if err != nil {
		return nil, err
	}
	operations := Diff(spec, r.Firewall.Fingerprint(plan), observed)

	// The packet filter goes in first. Doing it the other way round would leave a
	// window where the ingress interface is up and forwarding under whatever rules
	// happened to be loaded.
	if err := r.Firewall.Apply(ctx, plan); err != nil {
		return nil, fmt.Errorf("apply firewall: %w", err)
	}
	if err := r.Ingress.Apply(ctx, spec); err != nil {
		return nil, fmt.Errorf("apply ingress: %w", err)
	}
	return operations, nil
}

// compile turns a revision into the two artefacts the host needs. Both are derived
// before anything is applied, so a configuration error fails before the machine has
// been touched.
func (r HostReconciler) compile(ctx context.Context, state domain.DesiredState) (domain.FirewallPlan, domain.IngressSpec, error) {
	if r.Firewall == nil || r.Ingress == nil || r.Host == nil || r.ServerKey == nil {
		return domain.FirewallPlan{}, domain.IngressSpec{}, fmt.Errorf("host reconciler is not fully configured")
	}

	uplink, err := r.Host.UplinkInterface(ctx)
	if err != nil {
		return domain.FirewallPlan{}, domain.IngressSpec{}, fmt.Errorf("find uplink interface: %w", err)
	}
	plan, err := BuildFirewallPlan(state, uplink)
	if err != nil {
		return domain.FirewallPlan{}, domain.IngressSpec{}, err
	}

	privateKey, err := r.ServerKey.PrivateKey(ctx)
	if err != nil {
		return domain.FirewallPlan{}, domain.IngressSpec{}, err
	}
	spec, err := BuildIngressSpec(state, privateKey)
	if err != nil {
		return domain.FirewallPlan{}, domain.IngressSpec{}, err
	}
	return plan, spec, nil
}
