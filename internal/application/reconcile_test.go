package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type recordingFirewall struct {
	applied   []domain.FirewallPlan
	committed []domain.FirewallPlan
	err       error
	commitErr error
	// live is the fingerprint the host reports; empty means the table is absent.
	live string
	// repopulate is what Apply reports back while DNS dynamic sets need refilling.
	repopulate bool
}

func (f *recordingFirewall) Apply(_ context.Context, plan domain.FirewallPlan) (bool, error) {
	f.applied = append(f.applied, plan)
	return f.repopulate, f.err
}

func (f *recordingFirewall) CommitDNSRepopulation(_ context.Context, plan domain.FirewallPlan) error {
	f.committed = append(f.committed, plan)
	return f.commitErr
}

func (f *recordingFirewall) Observe(context.Context) (string, error) { return f.live, nil }

func (f *recordingFirewall) Fingerprint(domain.FirewallPlan) string { return "wanted" }

type recordingIngress struct {
	applied  []domain.IngressSpec
	err      error
	observed domain.IngressObservation
}

func (i *recordingIngress) Apply(_ context.Context, spec domain.IngressSpec) error {
	i.applied = append(i.applied, spec)
	return i.err
}

func (i *recordingIngress) Observe(context.Context, string) (domain.IngressObservation, error) {
	return i.observed, nil
}

type staticHost struct{ device string }

func (h staticHost) UplinkInterface(context.Context) (string, error) { return h.device, nil }

type staticKey struct{ key string }

func (k staticKey) PrivateKey(context.Context) (string, error) { return k.key, nil }

// hubKeyPair returns a private key and the desired state whose hub public key matches.
func hubKeyPair(t *testing.T) (string, domain.DesiredState) {
	t.Helper()
	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, clientPublic, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	state := domain.DesiredState{
		Revision: "r1",
		Hub: domain.Hub{
			Endpoint:        "vpn.example.test:51820",
			ServerPublicKey: publicKey,
			ClientCIDR:      "10.80.0.0/24",
			DNSAddress:      "10.80.0.1",
		},
		Devices: []domain.DeployedDevice{{
			ID: "macbook", Address: "10.80.0.2/32",
			PublicKey: clientPublic, Egress: domain.EgressDirect,
		}},
	}
	return privateKey, state
}

func newReconciler(key string, firewall *recordingFirewall, ingress *recordingIngress) HostReconciler {
	return HostReconciler{
		Firewall:  firewall,
		Ingress:   ingress,
		Host:      staticHost{device: "eth0"},
		ServerKey: staticKey{key: key},
	}
}

func TestApplyConfiguresFirewallAndIngress(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	firewall, ingress := &recordingFirewall{}, &recordingIngress{}

	if _, err := newReconciler(key, firewall, ingress).Apply(context.Background(), state); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(firewall.applied) != 1 || len(ingress.applied) != 1 {
		t.Fatalf("firewall applied %d times, ingress %d", len(firewall.applied), len(ingress.applied))
	}

	spec := ingress.applied[0]
	if spec.Address != "10.80.0.1/24" {
		t.Errorf("hub address = %q, want the DNS address masked to the client subnet", spec.Address)
	}
	if len(spec.Peers) != 1 {
		t.Fatalf("expected one peer, got %d", len(spec.Peers))
	}
	// A peer that could claim a wider range would be able to spoof another device.
	if got := spec.Peers[0].AllowedIPs; len(got) != 1 || got[0] != "10.80.0.2/32" {
		t.Errorf("AllowedIPs = %v, want only the profile's own host address", got)
	}
}

// Bringing the interface up before the policy is loaded would leave a window in which
// the hub forwards under whatever rules happened to be present.
func TestFirewallIsAppliedBeforeIngress(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	firewall := &recordingFirewall{err: fmt.Errorf("nft failed")}
	ingress := &recordingIngress{}

	if _, err := newReconciler(key, firewall, ingress).Apply(context.Background(), state); err == nil {
		t.Fatal("expected the firewall failure to abort the reconcile")
	}
	if len(ingress.applied) != 0 {
		t.Fatal("the ingress interface came up despite the policy failing to load")
	}
}

type recordingEgress struct {
	applied int
	err     error
}

func (e *recordingEgress) Apply(context.Context, []domain.EgressSpec) error {
	e.applied++
	return e.err
}

func (e *recordingEgress) Observe(context.Context) ([]string, error) { return nil, nil }

type recordingDNS struct {
	applied     int
	repopulated bool
	err         error
}

func (d *recordingDNS) Apply(_ context.Context, _ domain.DNSPlan, repopulate bool) error {
	d.applied++
	d.repopulated = repopulate
	return d.err
}

// A provider that is down must not stop the resolvers converging. Egress.Apply
// returning an error used to short-circuit the reconcile before DNS.Apply ran, so on
// a tick that rebuilt the firewall (the internal sets just emptied) private-zone
// traffic would fall through to the default egress until a clean tick. DNS must be
// applied regardless, and both errors reported.
func TestDNSAppliesEvenWhenEgressFails(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	egress := &recordingEgress{err: fmt.Errorf("provider unreachable")}
	dns := &recordingDNS{}
	r := newReconciler(key, &recordingFirewall{}, &recordingIngress{})
	r.Egress = egress
	r.DNS = dns

	_, err := r.Apply(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "provider unreachable") {
		t.Fatalf("Apply err = %v, want it to report the egress failure", err)
	}
	if egress.applied != 1 {
		t.Fatalf("Egress.Apply called %d times, want 1", egress.applied)
	}
	if dns.applied != 1 {
		t.Errorf("DNS.Apply called %d times, want 1 despite the egress failure", dns.applied)
	}
}

func TestDNSRepopulatesEvenWhenPostLoadFirewallCleanupFails(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	cleanupErr := errors.New("delete stale DNS conntrack: operation not permitted")
	dnsErr := errors.New("repopulate private DNS sets: dnsmasq failed")
	firewall := &recordingFirewall{repopulate: true, err: cleanupErr}
	dns := &recordingDNS{err: dnsErr}
	r := newReconciler(key, firewall, &recordingIngress{})
	r.DNS = dns

	_, err := r.Apply(context.Background(), state)
	if err == nil || !errors.Is(err, cleanupErr) || !errors.Is(err, dnsErr) {
		t.Fatalf("Apply error = %v, want joined firewall cleanup and DNS errors", err)
	}
	if dns.applied != 1 || !dns.repopulated {
		t.Fatalf("DNS apply = (%d, repopulate=%t), want one forced repopulation", dns.applied, dns.repopulated)
	}
	if len(firewall.committed) != 0 {
		t.Fatal("failed firewall cleanup was committed")
	}
}

func TestSuccessfulDNSRepopulationCommitsFirewallTransition(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	firewall := &recordingFirewall{repopulate: true}
	dns := &recordingDNS{}
	r := newReconciler(key, firewall, &recordingIngress{})
	r.DNS = dns

	if _, err := r.Apply(context.Background(), state); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if dns.applied != 1 || !dns.repopulated {
		t.Fatalf("DNS apply = (%d, repopulate=%t), want one forced repopulation", dns.applied, dns.repopulated)
	}
	if len(firewall.committed) != 1 {
		t.Fatalf("firewall transition committed %d times, want 1", len(firewall.committed))
	}
}

// A hub key that does not match the revision means every issued client profile names
// the wrong peer, so no handshake can ever succeed. Failing loudly beats a dead hub.
func TestMismatchedHubKeyIsRejected(t *testing.T) {
	t.Parallel()
	_, state := hubKeyPair(t)
	otherKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	firewall, ingress := &recordingFirewall{}, &recordingIngress{}

	_, err = newReconciler(otherKey, firewall, ingress).Apply(context.Background(), state)
	if err == nil {
		t.Fatal("expected a key mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want it to explain the mismatch", err)
	}
	if len(firewall.applied) != 0 {
		t.Error("nothing should have been applied: the revision is compiled before the host is touched")
	}
}

func TestPlanDoesNotTouchTheHost(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	firewall, ingress := &recordingFirewall{}, &recordingIngress{}

	operations, err := newReconciler(key, firewall, ingress).Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(operations) == 0 {
		t.Fatal("expected the plan to describe something")
	}
	if len(firewall.applied) != 0 || len(ingress.applied) != 0 {
		t.Fatal("Plan must not apply anything")
	}
}

func TestIncompleteReconcilerFailsBeforeDoingAnything(t *testing.T) {
	t.Parallel()
	_, state := hubKeyPair(t)
	if _, err := (HostReconciler{}).Apply(context.Background(), state); err == nil {
		t.Fatal("expected an unconfigured reconciler to refuse")
	}
}

// Revocation works by the device being absent from the revision, which must leave the
// interface with no peer for it.
func TestRevokedDeviceHasNoPeer(t *testing.T) {
	t.Parallel()
	key, state := hubKeyPair(t)
	state.Devices = nil
	firewall, ingress := &recordingFirewall{}, &recordingIngress{}

	if _, err := newReconciler(key, firewall, ingress).Apply(context.Background(), state); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ingress.applied[0].Peers) != 0 {
		t.Fatalf("expected no peers, got %+v", ingress.applied[0].Peers)
	}
}
