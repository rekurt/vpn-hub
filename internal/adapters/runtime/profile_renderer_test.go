package runtime

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func TestAmneziaProfileRenderer(t *testing.T) {
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := (AmneziaProfileRenderer{}).Render(domain.Hub{
		Endpoint: "vpn.example.test:51820", ServerPublicKey: "server", DNSAddress: "10.80.0.1", AWGInterface: map[string]string{"Jc": "4"},
	}, domain.DeviceProfile{Address: "10.80.0.2/32", ClientPrivateKey: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"[Interface]", "PrivateKey = " + privateKey, "Jc = 4", "[Peer]", "AllowedIPs = 0.0.0.0/0"} {
		if !strings.Contains(profile, wanted) {
			t.Fatalf("profile does not contain %q:\n%s", wanted, profile)
		}
	}
}
