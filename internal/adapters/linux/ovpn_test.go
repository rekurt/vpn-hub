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
}

func TestParseOpenVPNConfigRejectsExternalReferences(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, directive, want string
	}{
		{"relative auth file", "auth-user-pass credentials.txt", "external file reference"},
		{"absolute auth file", "auth-user-pass /etc/shadow", "external file reference"},
		{"proxy auth file", "http-proxy-user-pass proxy.auth", "external file reference"},
		{"pkcs12 file", "pkcs12 identity.p12", "external file reference"},
		{"crl verifier", "crl-verify revoked.pem", "external file reference"},
		{"askpass file", "askpass passphrase.txt", "external file reference"},
		{"script verifier", "tls-crypt-v2-verify /usr/local/bin/check", "external command reference"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseOpenVPNConfig(providerOVPN + test.directive + "\n")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseOpenVPNConfigRejectsPrefixedExternalReferences(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, directive, want string
	}{
		{"auth file", "--auth-user-pass credentials.txt", "external file reference"},
		{"proxy auth file", "--http-proxy-user-pass proxy.auth", "external file reference"},
		{"askpass file", "--askpass passphrase.txt", "external file reference"},
		{"pkcs12 file", "--pkcs12 identity.p12", "external file reference"},
		{"crl verifier", "--crl-verify revoked.pem", "external file reference"},
		{"script verifier", "--tls-crypt-v2-verify /usr/local/bin/check", "external command reference"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseOpenVPNConfig(providerOVPN + test.directive + "\n")
			if err == nil || !strings.Contains(err.Error(), "line") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want line evidence and %q", err, test.want)
			}
		})
	}
}

func TestParseOpenVPNConfigRejectsMalformedInlineBlocks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, config string
	}{
		{
			name: "self closing auth block bypass",
			config: providerOVPN + `<auth-user-pass/>
auth-user-pass credentials.txt
`,
		},
		{
			name: "tag with trailing content bypass",
			config: providerOVPN + `<ca>
certificate
</auth-user-pass/> ignored
auth-user-pass credentials.txt
`,
		},
		{
			name: "mismatched close",
			config: providerOVPN + `<ca>
certificate
</cert>
`,
		},
		{
			name: "unterminated block bypass",
			config: providerOVPN + `<ca>
certificate
auth-user-pass credentials.txt
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseOpenVPNConfig(test.config)
			if err == nil || !strings.Contains(err.Error(), "line") || !strings.Contains(err.Error(), "inline block") {
				t.Fatalf("error = %v, want inline block error with line evidence", err)
			}
		})
	}
}

func TestParseOpenVPNConfigAcceptsKnownTagAsOpaqueInlineCredentialPassword(t *testing.T) {
	t.Parallel()
	config := providerOVPN + `auth-user-pass
<auth-user-pass>
demo-user
<ca>
</auth-user-pass>
`

	tunnel, err := ParseOpenVPNConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Config != config {
		t.Fatal("the inline credential password was not preserved")
	}
}

func TestParseOpenVPNConfigAcceptsOpaqueInlineCredentialPassword(t *testing.T) {
	t.Parallel()
	config := providerOVPN + `auth-user-pass
<auth-user-pass>
demo-user
<value>
</auth-user-pass>
`

	tunnel, err := ParseOpenVPNConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Config != config {
		t.Fatal("the inline credential password was not preserved")
	}
}

func TestParseOpenVPNConfigRejectsCredentialBlockBypassWithTrailingClose(t *testing.T) {
	t.Parallel()
	_, err := ParseOpenVPNConfig(providerOVPN + `auth-user-pass
<auth-user-pass>
demo-user
</auth-user-pass/> ignored
auth-user-pass credentials.txt
`)
	if err == nil || !strings.Contains(err.Error(), "inline block") {
		t.Fatalf("error = %v, want inline block error", err)
	}
}

func TestParseOpenVPNConfigAcceptsTagLikeOpaqueInlineProxyCredentials(t *testing.T) {
	t.Parallel()
	config := providerOVPN + `<http-proxy-user-pass>
proxy-user
<ca>
</anything>
</http-proxy-user-pass>
`

	tunnel, err := ParseOpenVPNConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Config != config {
		t.Fatal("the inline proxy credentials were not preserved")
	}
}

func TestParseOpenVPNConfigAcceptsAdditionalInlineBlocks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, block, content string
	}{
		{"pkcs12", "pkcs12", "<binary-material>"},
		{"proxy credentials", "http-proxy-user-pass", "proxy-user\n<value>"},
		{"tls crypt v2", "tls-crypt-v2", "wrapped-key-material"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := providerOVPN + "<" + test.block + ">\n" + test.content + "\n</" + test.block + ">\n"
			tunnel, err := ParseOpenVPNConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			if tunnel.Config != config {
				t.Fatal("the inline block was not preserved")
			}
		})
	}
}

func TestParseOpenVPNConfigParsesRemoteInsideConnection(t *testing.T) {
	t.Parallel()
	config := providerOVPN + `<connection>
remote backup.example.net 443 tcp
</connection>
`

	tunnel, err := ParseOpenVPNConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnel.Remotes) != 2 {
		t.Fatalf("remotes = %+v", tunnel.Remotes)
	}
	remote := tunnel.Remotes[1]
	if remote.Host != "backup.example.net" || remote.Port != 443 || remote.Protocol != "tcp" {
		t.Errorf("remote = %+v", remote)
	}
}

func TestParseOpenVPNConfigRejectsExternalReferenceInsideConnection(t *testing.T) {
	t.Parallel()

	for _, directive := range []string{"auth-user-pass credentials.txt", "--auth-user-pass credentials.txt"} {
		directive := directive
		t.Run(directive, func(t *testing.T) {
			t.Parallel()
			_, err := ParseOpenVPNConfig(providerOVPN + "<connection>\n" + directive + "\n</connection>\n")
			if err == nil || !strings.Contains(err.Error(), "external file reference") {
				t.Fatalf("error = %v, want external file reference", err)
			}
		})
	}
}

func TestParseOpenVPNConfigRejectsMalformedConnectionBlocks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, config string
	}{
		{"malformed opener", providerOVPN + "<connection/>\n"},
		{"nested connection", providerOVPN + "<connection>\n<connection>\n</connection>\n</connection>\n"},
		{"unterminated connection", providerOVPN + "<connection>\nremote backup.example.net\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseOpenVPNConfig(test.config)
			if err == nil || !strings.Contains(err.Error(), "line") || !strings.Contains(err.Error(), "inline block") {
				t.Fatalf("error = %v, want inline block error with line evidence", err)
			}
		})
	}
}

func TestParseOpenVPNConfigAcceptsCompleteInlineCredentials(t *testing.T) {
	t.Parallel()
	config := providerOVPN + `auth-user-pass
<auth-user-pass>
demo-user
demo-password
</auth-user-pass>
`

	tunnel, err := ParseOpenVPNConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Config != config {
		t.Fatal("the inline credentials were not preserved")
	}
	if rendered := RenderOpenVPNConfig(tunnel, "ovpn0", "/run/vpn-hub/x.sock"); !strings.Contains(rendered, "demo-user\ndemo-password") {
		t.Fatal("the rendered configuration dropped the inline credentials")
	}
}

func TestParseOpenVPNConfigRejectsIncompleteInlineCredentials(t *testing.T) {
	t.Parallel()
	_, err := ParseOpenVPNConfig(providerOVPN + `auth-user-pass
<auth-user-pass>
demo-user
</auth-user-pass>
`)
	if err == nil || !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("error = %v, want unattended-prompt error", err)
	}
}

func TestParseOpenVPNConfigRejectsInlineCredentialsWithoutPassword(t *testing.T) {
	t.Parallel()
	_, err := ParseOpenVPNConfig(providerOVPN + `<auth-user-pass>
demo-user
</auth-user-pass>
`)
	if err == nil || !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("error = %v, want unattended-prompt error", err)
	}
}

func TestParseOpenVPNConfigRejectsAnyIncompleteInlineCredentialBlock(t *testing.T) {
	t.Parallel()
	_, err := ParseOpenVPNConfig(providerOVPN + `auth-user-pass
<auth-user-pass>
demo-user
demo-password
</auth-user-pass>
<auth-user-pass>
demo-user
</auth-user-pass>
`)
	if err == nil || !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("error = %v, want unattended-prompt error", err)
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
