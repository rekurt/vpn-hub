package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSSubscriptionFetcher(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://example"))
	}))
	defer server.Close()

	fetcher := HTTPSSubscriptionFetcher{Client: server.Client()}
	payload, err := fetcher.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "vless://example" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestHTTPSSubscriptionFetcherRejectsHTTP(t *testing.T) {
	_, err := (HTTPSSubscriptionFetcher{}).Fetch(context.Background(), "http://example.test/sub")
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Fetch() error = %v", err)
	}
}
