package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

type fakeFetcher struct {
	payload []byte
	err     error
}

func (f fakeFetcher) Fetch(context.Context, string) ([]byte, error) { return f.payload, f.err }

type recordingWriter struct {
	written []domain.ProxyTunnel
	err     error
}

func (w *recordingWriter) Write(_ context.Context, _ domain.Tunnel, chosen domain.ProxyTunnel) error {
	w.written = append(w.written, chosen)
	return w.err
}

func subscriptionTunnel() domain.Tunnel {
	return domain.Tunnel{
		ID: "provider", Type: domain.TunnelXray, Role: domain.RoleEgress,
		Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/sub"},
	}
}

func candidates(count int) []domain.ProxyTunnel {
	result := make([]domain.ProxyTunnel, 0, count)
	for index := range count {
		result = append(result, domain.ProxyTunnel{
			Protocol: "vless", Server: "node.example", Port: uint16(443 + index), UUID: "u",
		})
	}
	return result
}

func TestRefreshPromotesOnlyAProvenCandidate(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	refresher := SubscriptionRefresher{
		Fetch: fakeFetcher{payload: []byte("payload")},
		Parse: func([]byte) ([]domain.ProxyTunnel, error) { return candidates(3), nil },
		Prove: func(_ context.Context, list []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			// The second one works; the first was rejected.
			return list[1], []string{"node.example:443: refused"}, nil
		},
		Store: writer,
	}

	chosen, rejected, err := refresher.Refresh(context.Background(), subscriptionTunnel())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if chosen.Port != 444 {
		t.Errorf("promoted %d, want the candidate that worked", chosen.Port)
	}
	if len(writer.written) != 1 || writer.written[0].Port != 444 {
		t.Errorf("stored %+v", writer.written)
	}
	// A rejection nobody can read is a rejection nobody can act on.
	if len(rejected) != 1 {
		t.Errorf("rejections = %v", rejected)
	}
}

// A subscription that offers nothing working is a reason to keep what already works,
// not to replace it.
func TestNothingIsStoredWhenNoCandidateWorks(t *testing.T) {
	t.Parallel()
	writer := &recordingWriter{}
	refresher := SubscriptionRefresher{
		Fetch: fakeFetcher{payload: []byte("payload")},
		Parse: func([]byte) ([]domain.ProxyTunnel, error) { return candidates(2), nil },
		Prove: func(context.Context, []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			return domain.ProxyTunnel{}, []string{"a: refused", "b: timed out"}, errors.New("no candidate carried traffic")
		},
		Store: writer,
	}

	_, rejected, err := refresher.Refresh(context.Background(), subscriptionTunnel())
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(writer.written) != 0 {
		t.Fatal("the active upstream must be left alone")
	}
	if len(rejected) != 2 {
		t.Errorf("the reasons must survive the failure: %v", rejected)
	}
}

func TestRefreshRejectsNonSubscriptions(t *testing.T) {
	t.Parallel()
	tunnel := subscriptionTunnel()
	tunnel.Source.Kind = domain.SourceConfig

	refresher := SubscriptionRefresher{
		Fetch: fakeFetcher{}, Parse: func([]byte) ([]domain.ProxyTunnel, error) { return nil, nil },
		Prove: func(context.Context, []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			return domain.ProxyTunnel{}, nil, nil
		},
		Store: &recordingWriter{},
	}
	if _, _, err := refresher.Refresh(context.Background(), tunnel); err == nil {
		t.Fatal("expected a non-subscription source to be refused")
	}
}

// A fetch that fails must not reach the prover, or a network blip would look like a
// dead provider.
func TestAFailedFetchStopsBeforeProving(t *testing.T) {
	t.Parallel()
	proved := false
	refresher := SubscriptionRefresher{
		Fetch: fakeFetcher{err: errors.New("connection reset")},
		Parse: func([]byte) ([]domain.ProxyTunnel, error) { return candidates(1), nil },
		Prove: func(context.Context, []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
			proved = true
			return domain.ProxyTunnel{}, nil, nil
		},
		Store: &recordingWriter{},
	}

	_, _, err := refresher.Refresh(context.Background(), subscriptionTunnel())
	if err == nil || !strings.Contains(err.Error(), "fetch subscription") {
		t.Fatalf("error = %v", err)
	}
	if proved {
		t.Fatal("a failed fetch must not be tried as a candidate")
	}
}
