package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The subscription fetcher runs as root in the host's main namespace, so a redirect
// (or DNS answer) pointing at the metadata service or the private network it gateways
// must be refused at the dial. refusePrivateDial is the socket-level guard.
func TestRefusePrivateDial(t *testing.T) {
	t.Parallel()
	refused := map[string]string{
		"metadata link-local":  "169.254.169.254:443",
		"rfc1918 ten":          "10.20.0.53:443",
		"rfc1918 192.168":      "192.168.1.1:443",
		"loopback":             "127.0.0.1:443",
		"unspecified":          "0.0.0.0:443",
		"ipv6 loopback":        "[::1]:443",
		"ipv6 link-local":      "[fe80::1]:443",
		"ipv6 unique-local":    "[fd00::1]:443",
		"not an ip (hostname)": "example.com:443",
	}
	for name, address := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			t.Parallel()
			if err := refusePrivateDial("tcp", address, nil); err == nil {
				t.Fatalf("refusePrivateDial(%q) = nil, want it refused", address)
			}
		})
	}

	allowed := map[string]string{
		"public v4": "1.1.1.1:443",
		"public v6": "[2606:4700:4700::1111]:443",
	}
	for name, address := range allowed {
		t.Run("allowed/"+name, func(t *testing.T) {
			t.Parallel()
			if err := refusePrivateDial("tcp", address, nil); err != nil {
				t.Fatalf("refusePrivateDial(%q) = %v, want it allowed", address, err)
			}
		})
	}
}

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
