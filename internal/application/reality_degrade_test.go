package application

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type failingKeyStore struct{ err error }

func (s failingKeyStore) PrivateKey(context.Context) (string, error) { return "", s.err }

type recordingReality struct {
	specs []domain.RealityIngressSpec
	// applied is what a listener is reported to be running, empty for none.
	applied string
}

func (r *recordingReality) Apply(_ context.Context, spec domain.RealityIngressSpec) error {
	r.specs = append(r.specs, spec)
	return nil
}

// Fingerprint stands in for the rendered configuration's digest: any stable
// function of the spec answers the question the diff asks of it.
func (r *recordingReality) Fingerprint(spec domain.RealityIngressSpec) string {
	if !spec.Enabled {
		return ""
	}
	return spec.ServerName + "/" + strconv.Itoa(len(spec.Users))
}

func (r *recordingReality) Applied(context.Context) (string, error) { return r.applied, nil }

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

// A dry run has to see what a real pass would hit. The fallback failure is
// deliberately not fatal, but `reconcile --dry-run` answering "nothing to do"
// would hide a failure that repeats on every tick with TCP/443 staying shut.
func TestADryRunReportsTheMissingRealityKey(t *testing.T) {
	t.Parallel()
	reconciler, state, _, _, _ := fallbackReconciler(t, failingKeyStore{
		err: errors.New("no REALITY key at /etc/vpn-hub/reality.key"),
	})

	_, err := reconciler.Plan(context.Background(), state)
	if err == nil {
		t.Fatal("the dry run reported success while the fallback could not be compiled")
	}
	if !strings.Contains(err.Error(), "REALITY key") {
		t.Fatalf("the reason did not survive: %v", err)
	}
}

// The fallback used to be the one component nothing observed, so a dry run
// reported a clean host while a real pass would restart the listener, and one
// that someone stopped was never mentioned as drift.
func TestTheFallbackListenerIsPartOfThePlan(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		running string
		want    domain.OperationKind
	}{
		"a listener that was stopped is reported":    {running: "", want: domain.OpCreate},
		"one started from another configuration too": {running: "stale", want: domain.OpUpdate},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			privateKey, state := hubKeyPair(t)
			state.Hub.Fallback.Reality = domain.RealityFallback{
				Enabled: true, ServerName: "www.example.com",
			}
			realityKey, _, err := domain.GenerateRealityKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			reality := &recordingReality{applied: test.running}
			reconciler := newReconciler(privateKey, &recordingFirewall{live: "wanted"}, &recordingIngress{
				observed: domain.IngressObservation{Exists: true},
			})
			reconciler.Reality = reality
			reconciler.RealityKey = staticKey{key: realityKey}

			operations, err := reconciler.Plan(context.Background(), state)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			var found *domain.Operation
			for index, operation := range operations {
				if operation.Resource.Type == "reality" {
					found = &operations[index]
				}
			}
			if found == nil {
				t.Fatalf("the fallback is absent from the plan: %v", operations)
			}
			if found.Kind != test.want {
				t.Errorf("kind = %q, want %q", found.Kind, test.want)
			}
		})
	}
}

// A listener that is up while the revision asks for none has to be reported, and
// that includes one whose configuration the hub has no record of: started by
// hand, or left from a pass that died between starting it and recording it.
// Reporting nothing there would leave TCP/443 open with the fallback switched
// off and every dry run calling the host clean.
func TestAListenerNobodyAskedForIsReported(t *testing.T) {
	t.Parallel()
	privateKey, state := hubKeyPair(t)
	// The revision does not ask for a fallback at all.
	reality := &recordingReality{applied: "running-unknown"}
	reconciler := newReconciler(privateKey, &recordingFirewall{live: "wanted"}, &recordingIngress{
		observed: domain.IngressObservation{Exists: true},
	})
	reconciler.Reality = reality

	operations, err := reconciler.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, operation := range operations {
		if operation.Resource.Type == "reality" {
			if operation.Kind != domain.OpDelete {
				t.Errorf("kind = %q, want %q", operation.Kind, domain.OpDelete)
			}
			return
		}
	}
	t.Fatalf("a running listener was not reported against a revision that wants none: %v", operations)
}

// And a hub whose listener is running exactly what the revision asks for has
// nothing to report -- otherwise every pass would claim drift forever.
func TestAConvergedFallbackIsNotDrift(t *testing.T) {
	t.Parallel()
	privateKey, state := hubKeyPair(t)
	state.Hub.Fallback.Reality = domain.RealityFallback{Enabled: true, ServerName: "www.example.com"}

	realityKey, _, err := domain.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	reality := &recordingReality{}
	reconciler := newReconciler(privateKey, &recordingFirewall{live: "wanted"}, &recordingIngress{
		observed: domain.IngressObservation{Exists: true},
	})
	reconciler.Reality = reality
	reconciler.RealityKey = staticKey{key: realityKey}

	// What the listener reports once it is running the compiled spec.
	compiled, compileErr := reconciler.compile(context.Background(), state)
	if compileErr != nil {
		t.Fatal(compileErr)
	}
	reality.applied = reality.Fingerprint(compiled.reality)

	operations, err := reconciler.Plan(context.Background(), state)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, operation := range operations {
		if operation.Resource.Type == "reality" {
			t.Fatalf("a converged listener was reported as drift: %v", operation)
		}
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
