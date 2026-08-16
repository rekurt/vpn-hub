package runtime_test

import (
	"strings"
	"testing"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/domain"
)

func fallbackHub(t *testing.T) domain.Hub {
	t.Helper()
	_, serverPublicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return domain.Hub{
		Endpoint:        "vpn.example.test:51820",
		ServerPublicKey: serverPublicKey,
		ClientCIDR:      "10.80.0.0/24",
		DNSAddress:      "10.80.0.1",
		Fallback: domain.IngressFallback{
			UDP443:  true,
			Reality: domain.RealityFallback{Enabled: true, ServerName: "www.example.com"},
		},
	}
}

// The link the hub hands a device and the link a provider hands the hub are the
// same format, so the parser the hub already trusts is the right judge of whether
// the renderer produced something a client can use.
func TestRealityLinkRoundTripsThroughTheParser(t *testing.T) {
	t.Parallel()
	hub := fallbackHub(t)
	privateKey, publicKey, err := domain.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, devicePublicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := domain.RealityUserUUID(privateKey, "macbook", devicePublicKey)
	if err != nil {
		t.Fatal(err)
	}

	link, err := runtimeadapter.RealityProfileRenderer{}.Link(hub, "macbook", uuid, publicKey)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	parsed, err := linux.ParseVLESS(link)
	if err != nil {
		t.Fatalf("the hub's own parser rejects the link it issued: %v\n%s", err, link)
	}
	if parsed.Server != "vpn.example.test" || parsed.Port != domain.RealityPort {
		t.Errorf("link points at %s:%d", parsed.Server, parsed.Port)
	}
	if parsed.UUID != uuid {
		t.Errorf("credential = %q, want %q", parsed.UUID, uuid)
	}
	if parsed.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q; server and client must agree or the tunnel carries nothing", parsed.Flow)
	}
	if !parsed.TLS.Reality.Enabled || parsed.TLS.Reality.PublicKey != publicKey {
		t.Errorf("reality settings did not survive: %+v", parsed.TLS)
	}
	if parsed.TLS.Reality.ShortID != domain.RealityShortID(publicKey) {
		t.Errorf("short id = %q, want the one derived from the key", parsed.TLS.Reality.ShortID)
	}
	if parsed.TLS.ServerName != "www.example.com" {
		t.Errorf("sni = %q", parsed.TLS.ServerName)
	}
	// The private key must never leave the hub.
	if strings.Contains(link, privateKey) {
		t.Fatal("the link carries the hub's private key")
	}
}

func TestRealityLinkRefusedWhenTheFallbackIsOff(t *testing.T) {
	t.Parallel()
	hub := fallbackHub(t)
	hub.Fallback.Reality.Enabled = false
	if _, err := (runtimeadapter.RealityProfileRenderer{}).Link(hub, "macbook", "u", "k"); err == nil {
		t.Fatal("a link was issued for a listener that is not running")
	}
}

// The alternate profile differs from the ordinary one in exactly one line, which
// is what makes it worth issuing rather than asking someone to edit a config on a
// phone.
func TestAltPortProfileOnlyMovesTheEndpoint(t *testing.T) {
	t.Parallel()
	hub := fallbackHub(t)
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ordinary, err := runtimeadapter.AmneziaProfileRenderer{}.Render(hub, "10.80.0.2/32", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := runtimeadapter.AltPortProfile(hub, "10.80.0.2/32", privateKey)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if !strings.Contains(alternate, "Endpoint = vpn.example.test:443\n") {
		t.Fatalf("the alternate profile does not point at 443:\n%s", alternate)
	}
	if strings.Contains(alternate, "Endpoint = vpn.example.test:51820\n") {
		t.Error("the alternate profile still carries the blocked port")
	}

	ordinaryLines := strings.Split(ordinary, "\n")
	alternateLines := strings.Split(alternate, "\n")
	if len(ordinaryLines) != len(alternateLines) {
		t.Fatalf("the profiles differ in length: %d vs %d", len(ordinaryLines), len(alternateLines))
	}
	differences := 0
	for index := range ordinaryLines {
		if ordinaryLines[index] != alternateLines[index] {
			differences++
		}
	}
	if differences != 1 {
		t.Errorf("the profiles differ on %d lines, want only the endpoint", differences)
	}
}

func TestAltPortProfileRefusedWhenTheFallbackIsOff(t *testing.T) {
	t.Parallel()
	hub := fallbackHub(t)
	hub.Fallback.UDP443 = false
	if _, err := runtimeadapter.AltPortProfile(hub, "10.80.0.2/32", "key"); err == nil {
		t.Fatal("a profile was issued for a port that is not redirected")
	}
}
