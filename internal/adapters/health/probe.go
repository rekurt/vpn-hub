package health

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"vpn-hub/internal/domain"
)

type ProbeChecker struct {
	Timeout time.Duration
}

func (p ProbeChecker) Check(ctx context.Context, tunnel domain.Tunnel) (domain.TunnelHealth, error) {
	checkedAt := time.Now().UTC()
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	health := domain.TunnelHealth{TunnelID: tunnel.ID, CheckedAt: checkedAt, Healthy: true}

	if tunnel.Health.TCPAddress != "" {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", tunnel.Health.TCPAddress)
		if err != nil {
			health.Healthy = false
			health.Reason = "tcp probe: " + err.Error()
			return health, nil
		}
		_ = conn.Close()
	}
	if tunnel.Health.HTTPSURL != "" {
		client := &http.Client{Timeout: timeout}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, tunnel.Health.HTTPSURL, nil)
		if err != nil {
			return health, fmt.Errorf("build HTTPS probe: %w", err)
		}
		response, err := client.Do(request)
		if err != nil {
			health.Healthy = false
			health.Reason = "https probe: " + err.Error()
			return health, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusBadRequest {
			health.Healthy = false
			health.Reason = "https probe returned " + response.Status
		}
	}
	if tunnel.Health.DNSName != "" {
		resolver := net.DefaultResolver
		if _, err := resolver.LookupHost(ctx, tunnel.Health.DNSName); err != nil {
			health.Healthy = false
			health.Reason = "dns probe: " + err.Error()
		}
	}
	return health, nil
}

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
	defer response.Body.Close()
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
