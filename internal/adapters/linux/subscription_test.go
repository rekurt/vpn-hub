package linux

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

const subscriptionBody = plainLink + "\n" + websocketLink + "\n"

func TestParsePlainSubscription(t *testing.T) {
	t.Parallel()
	tunnels, err := ParseSubscription([]byte(subscriptionBody))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(tunnels) != 2 {
		t.Fatalf("expected both links, got %d", len(tunnels))
	}
}

// Providers usually base64 the whole document, in whichever variant their tooling
// produces.
func TestParseEncodedSubscription(t *testing.T) {
	t.Parallel()
	for name, encoding := range map[string]*base64.Encoding{
		"standard":          base64.StdEncoding,
		"standard unpadded": base64.RawStdEncoding,
		"url-safe":          base64.URLEncoding,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tunnels, err := ParseSubscription([]byte(encoding.EncodeToString([]byte(subscriptionBody))))
			if err != nil {
				t.Fatalf("ParseSubscription: %v", err)
			}
			if len(tunnels) != 2 {
				t.Fatalf("expected both links, got %d", len(tunnels))
			}
		})
	}
}

// A provider adding a protocol the hub cannot use should not cost the ones it can.
func TestUnusableEntriesAreSkippedNotFatal(t *testing.T) {
	t.Parallel()
	mixed := "ss://something\n" + plainLink + "\nvmess://other\n"
	tunnels, err := ParseSubscription([]byte(mixed))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("expected the one usable link, got %d", len(tunnels))
	}
}

func TestSubscriptionWithNothingUsableIsAnError(t *testing.T) {
	t.Parallel()
	_, err := ParseSubscription([]byte("ss://a\nvmess://b\n"))
	if err == nil {
		t.Fatal("expected an error naming the problem")
	}
	if !strings.Contains(err.Error(), "no usable links") {
		t.Fatalf("error = %v", err)
	}
}

func TestEmptySubscriptionIsAnError(t *testing.T) {
	t.Parallel()
	if _, err := ParseSubscription([]byte("   \n")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSubscriptionCandidateLimit(t *testing.T) {
	t.Parallel()
	var body strings.Builder
	for index := range 33 {
		fmt.Fprintf(&body, "vless://candidate-%d@node-%d.example.net:443?encryption=none&type=tcp\n", index, index)
	}

	_, err := ParseSubscription([]byte(body.String()))
	if err == nil || !strings.Contains(err.Error(), "more than 32 usable candidates") {
		t.Fatalf("error = %v", err)
	}
}

func TestSubscriptionLineLimit(t *testing.T) {
	t.Parallel()
	_, err := ParseSubscription([]byte(strings.Repeat("x", 8193)))
	if err == nil || !strings.Contains(err.Error(), "line exceeds 8192 bytes") {
		t.Fatalf("error = %v", err)
	}
}

// What the hub stores stays in the format an operator can read and paste elsewhere,
// so a link must survive the round trip.
func TestLinksSurviveARoundTrip(t *testing.T) {
	t.Parallel()
	for name, link := range map[string]string{
		"reality":   realityLink,
		"websocket": websocketLink,
		"plain":     plainLink,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			parsed, err := ParseVLESS(link)
			if err != nil {
				t.Fatal(err)
			}
			rendered, err := RenderVLESS(parsed)
			if err != nil {
				t.Fatalf("RenderVLESS: %v", err)
			}
			again, err := ParseVLESS(rendered)
			if err != nil {
				t.Fatalf("the rendered link does not parse: %v\n%s", err, rendered)
			}
			if again != parsed {
				t.Errorf("the round trip changed the tunnel:\n%+v\n%+v", parsed, again)
			}
		})
	}
}
