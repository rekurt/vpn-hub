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
		client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: httpsOnlyRedirect}
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

// httpsOnlyRedirect keeps the HTTPS-only guarantee across redirects. Without it a
// hostile or hijacked provider could answer a 302 to http://169.254.169.254/… or an
// internal http://10.x/… and turn this fetch -- run as root in the host's main
// namespace -- into a blind request against the metadata service or the private
// network the hub is meant to gateway. The scheme check on the original URL alone
// does not cover where a redirect points.
func httpsOnlyRedirect(request *http.Request, _ []*http.Request) error {
	if request.URL.Scheme != "https" {
		return fmt.Errorf("subscription redirect to non-HTTPS %q refused", request.URL.Scheme)
	}
	return nil
}
