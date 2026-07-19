// Package health fetches what a provider publishes. Judging whether a tunnel works
// is not done here: that has to happen inside the tunnel's own namespace, which is
// the adapters/linux package's business.
package health

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPSSubscriptionFetcher struct {
	Client  *http.Client
	MaxSize int64
}

func (f HTTPSSubscriptionFetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("subscription URL must use HTTPS")
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	maxSize := f.MaxSize
	if maxSize == 0 {
		maxSize = 1 << 20
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build subscription request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch subscription: %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read subscription: %w", err)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("subscription exceeds %d bytes", maxSize)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("subscription is empty")
	}
	return data, nil
}
