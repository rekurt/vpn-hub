package linux

import (
	"strings"
	"testing"
)

// The shape providers ship: inline keys, options the hub does not interpret, and a
// remote line with protocol.
const providerOVPN = `client
dev tun
proto udp
remote vpn.example.net 1194 udp
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
redirect-gateway def1
<ca>
-----BEGIN CERTIFICATE-----
MIIBnotarealcertificate
-----END CERTIFICATE-----
</ca>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
-----END OpenVPN Static key V1-----
</tls-crypt>
`

func TestParseOpenVPNConfig(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseOpenVPNConfig(providerOVPN)
	if err != nil {
		t.Fatalf("ParseOpenVPNConfig: %v", err)
	}
	if len(tunnel.Remotes) != 1 {
		t.Fatalf("remotes = %+v", tunnel.Remotes)
	}
	remote := tunnel.Remotes[0]
	if remote.Host != "vpn.example.net" || remote.Port != 1194 || remote.Protocol != "udp" {
		t.Errorf("remote = %+v", remote)
	}
	if !tunnel.RedirectsGateway {
		t.Error("redirect-gateway was not noticed")
	}
	// The provider's own text has to survive: OpenVPN understands its options better
	// than a reimplementation would.
	if !strings.Contains(tunnel.Config, "cipher AES-256-GCM") {
		t.Error("the original configuration was not preserved")
	}
}

// Inline blocks can contain anything, including words that look like directives.
func TestInlineBlocksAreNotInterpreted(t *testing.T) {
	t.Parallel()
	tricky := providerOVPN + "<cert>\nremote evil.example.net 443 tcp\n</cert>\n"
	tunnel, err := ParseOpenVPNConfig(tricky)
	if err != nil {
		t.Fatal(err)
	}
	for _, remote := range tunnel.Remotes {
		if remote.Host == "evil.example.net" {
			t.Fatal("a line inside an inline block was read as a directive")
		}
	}
}

func TestRemoteDefaultsMatchOpenVPN(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseOpenVPNConfig("remote vpn.example.net\n")
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Remotes[0].Port != 1194 || tunnel.Remotes[0].Protocol != "udp" {
		t.Errorf("defaults = %+v", tunnel.Remotes[0])
	}
}

// An unattended service cannot answer a prompt, so a configuration that would ask
// has to be refused where it can still be explained.
func TestCredentialPromptIsRefused(t *testing.T) {
	t.Parallel()
	_, err := ParseOpenVPNConfig(providerOVPN + "auth-user-pass\n")
	if err == nil || !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("error = %v", err)
	}
	// With a file it is fine: the credentials are already on the host.
	if _, err := ParseOpenVPNConfig(providerOVPN + "auth-user-pass /etc/vpn-hub/creds\n"); err != nil {
		t.Fatalf("a credentials file should be accepted: %v", err)
	}
}

func TestConfigurationWithoutARemoteIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := ParseOpenVPNConfig("client\ndev tun\n"); err == nil {
		t.Fatal("expected a configuration with nowhere to connect to be refused")
	}
}

func TestRenderedConfigKeepsTheProviderAndAddsTheHubsNeeds(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseOpenVPNConfig(providerOVPN)
	if err != nil {
		t.Fatal(err)
	}
	rendered := RenderOpenVPNConfig(tunnel, "ovpn0", "/run/vpn-hub/x.sock")

	if !strings.Contains(rendered, "cipher AES-256-GCM") {
		t.Error("the provider's options were dropped")
	}
	for _, wanted := range []string{"dev ovpn0", "management /run/vpn-hub/x.sock unix"} {
		if !strings.Contains(rendered, wanted) {
			t.Errorf("missing %q", wanted)
		}
	}
}

// The management socket's vocabulary names the stage, which beats "not working".
func TestParseManagementState(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ output, want string }{
		"connected": {">INFO:OpenVPN Management Interface\n1752900000,CONNECTED,SUCCESS,10.8.0.2,\nEND\n", "CONNECTED"},
		"stuck":     {"1752900000,WAIT,,,\nEND\n", "WAIT"},
		"resolving": {"1752900000,RESOLVE,,,\nEND\n", "RESOLVE"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state, err := parseOpenVPNState(test.output)
			if err != nil {
				t.Fatalf("parseOpenVPNState: %v", err)
			}
			if state != test.want {
				t.Errorf("state = %q, want %q", state, test.want)
			}
		})
	}

	if _, err := parseOpenVPNState(">INFO:only chatter\nEND\n"); err == nil {
		t.Error("expected an error when no state was reported")
	}
}
