package application

import (
	"context"
	"fmt"

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
}

func (r HostReconciler) Plan(ctx context.Context, state domain.DesiredState) ([]domain.Operation, error) {
	plan, spec, err := r.compile(ctx, state)
	if err != nil {
		return nil, err
	}

	operations := []domain.Operation{{
		Kind:        "nftables",
		Resource:    "inet vpn_hub",
		Description: fmt.Sprintf("install policy for %d egress group(s) with a default-drop forward chain", len(plan.Egresses)),
	}, {
		Kind:        "ingress",
		Resource:    spec.Interface,
		Description: fmt.Sprintf("configure %s on port %d with %d peer(s)", spec.Address, spec.ListenPort, len(spec.Peers)),
	}}
	return operations, nil
}

func (r HostReconciler) Apply(ctx context.Context, state domain.DesiredState) error {
	plan, spec, err := r.compile(ctx, state)
	if err != nil {
		return err
	}

	// The packet filter goes in first. Doing it the other way round would leave a
	// window where the ingress interface is up and forwarding under whatever rules
	// happened to be loaded.
	if err := r.Firewall.Apply(ctx, plan); err != nil {
		return fmt.Errorf("apply firewall: %w", err)
	}
	if err := r.Ingress.Apply(ctx, spec); err != nil {
		return fmt.Errorf("apply ingress: %w", err)
	}
	return nil
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
