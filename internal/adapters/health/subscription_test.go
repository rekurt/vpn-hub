package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchRejectsNonHTTPSURL(t *testing.T) {
	t.Parallel()
	if _, err := (HTTPSSubscriptionFetcher{}).Fetch(context.Background(), "http://example.test/sub"); err == nil {
		t.Fatal("expected an http:// URL to be refused")
	}
}

// A hostile provider must not be able to redirect the fetch onto an internal or
// metadata endpoint: the scheme guarantee holds across redirects.
func TestFetchRefusesRedirectToNonHTTPS(t *testing.T) {
	t.Parallel()
	var reached bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte("vless://x@1.2.3.4:443"))
	}))
	defer internal.Close()

	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", internal.URL) // http:// target
		w.WriteHeader(http.StatusFound)
	}))
	defer provider.Close()

	// Trust the test TLS cert but keep the production redirect policy.
	client := provider.Client()
	client.CheckRedirect = httpsOnlyRedirect
	fetcher := HTTPSSubscriptionFetcher{Client: client}

	_, err := fetcher.Fetch(context.Background(), provider.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected the redirect to be refused, got %v", err)
	}
	if reached {
		t.Fatal("the internal endpoint was reached despite the non-HTTPS redirect")
	}
}
