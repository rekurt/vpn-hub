package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type failingKeyStore struct{ err error }

func (s failingKeyStore) PrivateKey(context.Context) (string, error) { return "", s.err }

type recordingReality struct{ specs []domain.RealityIngressSpec }

func (r *recordingReality) Apply(_ context.Context, spec domain.RealityIngressSpec) error {
	r.specs = append(r.specs, spec)
	return nil
}

func fallbackReconciler(t *testing.T, keys failingKeyStore) (HostReconciler, domain.DesiredState, *recordingFirewall, *recordingIngress, *recordingReality) {
	t.Helper()
	privateKey, state := hubKeyPair(t)
	state.Hub.Fallback.Reality = domain.RealityFallback{Enabled: true, ServerName: "www.example.com"}

	firewall := &recordingFirewall{}
	ingress := &recordingIngress{}
	reality := &recordingReality{}
	reconciler := newReconciler(privateKey, firewall, ingress)
	reconciler.Reality = reality
	reconciler.RealityKey = keys
	return reconciler, state, firewall, ingress, reality
}

// A fallback that cannot be compiled -- almost always a key nobody generated --
// used to fail the whole compile, which meant the agent stopped converging the
// firewall, the ingress, the tunnels and DNS. Every tick, silently, until someone
// noticed the hub had drifted. An alternative way in is not worth the hub.
func TestAMissingRealityKeyStillConvergesEverythingElse(t *testing.T) {
	t.Parallel()
	missing := errors.New("no REALITY key at /etc/vpn-hub/reality.key")
	reconciler, state, firewall, ingress, reality := fallbackReconciler(t, failingKeyStore{err: missing})

	_, err := reconciler.Apply(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "REALITY key") {
		t.Fatalf("the missing key was not reported: %v", err)
	}
	if len(firewall.applied) == 0 {
		t.Error("the firewall did not converge because a fallback key was missing")
	}
	if len(ingress.applied) == 0 {
		t.Error("the ingress did not converge because a fallback key was missing")
	}
	if len(reality.specs) != 1 || reality.specs[0].Enabled {
		t.Fatalf("the listener was not asked to stay down: %+v", reality.specs)
	}
}

// And the port follows: a listener that cannot run must not leave 443 accepted
// with nothing behind it.
func TestAMissingRealityKeyLeaves443Closed(t *testing.T) {
	t.Parallel()
	reconciler, state, _, _, _ := fallbackReconciler(t, failingKeyStore{err: errors.New("no key")})

	compiled, err := reconciler.compile(context.Background(), state)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compiled.firewall.RealityPort != 0 {
		t.Errorf("443 is accepted with no listener behind it: port %d", compiled.firewall.RealityPort)
	}
	if compiled.realityErr == nil {
		t.Error("the reason was not carried for reporting")
	}
}
