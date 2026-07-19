package application

import (
	"context"
	"fmt"
	"time"

	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
)

// SubscriptionRefresher replaces a tunnel's upstream from its provider's
// subscription, but only with one that has been shown to work.
//
// The order matters more than anything else here. A subscription changes at the
// provider without warning, and the tunnel a candidate would replace is the one
// carrying traffic; applying first and checking afterwards means finding out by
// losing the connection. So: fetch, parse, prove in isolation, and only then promote.
type SubscriptionRefresher struct {
	Fetch ports.SubscriptionFetcher
	Parse func([]byte) ([]domain.ProxyTunnel, error)
	Prove func(ctx context.Context, candidates []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error)
	Store ports.UpstreamWriter
	Now   func() time.Time
}

// Refresh updates one tunnel. It returns the chosen candidate and the reasons any
// others were rejected, so a rejection can be read rather than guessed at.
func (r SubscriptionRefresher) Refresh(ctx context.Context, tunnel domain.Tunnel) (domain.ProxyTunnel, []string, error) {
	if r.Fetch == nil || r.Parse == nil || r.Prove == nil || r.Store == nil {
		return domain.ProxyTunnel{}, nil, fmt.Errorf("subscription refresher is not fully configured")
	}
	if tunnel.Source.Kind != domain.SourceSubscription {
		return domain.ProxyTunnel{}, nil, fmt.Errorf("tunnel %q is not a subscription", tunnel.ID)
	}

	payload, err := r.Fetch.Fetch(ctx, tunnel.Source.Value)
	if err != nil {
		return domain.ProxyTunnel{}, nil, fmt.Errorf("fetch subscription: %w", err)
	}
	candidates, err := r.Parse(payload)
	if err != nil {
		return domain.ProxyTunnel{}, nil, fmt.Errorf("read subscription: %w", err)
	}

	chosen, rejected, err := r.Prove(ctx, candidates)
	if err != nil {
		// The active upstream is left exactly as it was: a subscription that offers
		// nothing working is a reason to keep what already works, not to replace it.
		return domain.ProxyTunnel{}, rejected, err
	}

	if err := r.Store.Write(ctx, tunnel, chosen); err != nil {
		return domain.ProxyTunnel{}, rejected, fmt.Errorf("save the chosen candidate: %w", err)
	}
	return chosen, rejected, nil
}
