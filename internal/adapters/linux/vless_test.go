package linux

import (
	"encoding/json"
	"strings"
	"testing"
)

// Shapes real providers ship, including the fragment and extra parameters that are
// none of the hub's business.
const (
	realityLink = "vless://7a1f8c2e-0000-4000-8000-000000000001@node.example.net:443" +
		"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome" +
		"&pbk=xY3z_publickey_example&sid=0123abcd&type=tcp&flow=xtls-rprx-vision#NL-01"
	websocketLink = "vless://7a1f8c2e-0000-4000-8000-000000000002@node.example.net:8443" +
		"?encryption=none&security=tls&sni=cdn.example.net&type=ws&path=%2Fray&host=cdn.example.net#WS"
	plainLink = "vless://7a1f8c2e-0000-4000-8000-000000000003@node.example.net:80?encryption=none&type=tcp"
)

func TestParseRealityLink(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseVLESS(realityLink)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}

	if tunnel.Server != "node.example.net" || tunnel.Port != 443 {
		t.Errorf("endpoint = %s:%d", tunnel.Server, tunnel.Port)
	}
	if tunnel.UUID != "7a1f8c2e-0000-4000-8000-000000000001" {
		t.Errorf("UUID = %q", tunnel.UUID)
	}
	if tunnel.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", tunnel.Flow)
	}
	if !tunnel.TLS.Reality.Enabled || tunnel.TLS.Reality.PublicKey == "" || tunnel.TLS.Reality.ShortID != "0123abcd" {
		t.Errorf("REALITY = %+v", tunnel.TLS.Reality)
	}
	if tunnel.TLS.ServerName != "www.microsoft.com" || tunnel.TLS.Fingerprint != "chrome" {
		t.Errorf("TLS = %+v", tunnel.TLS)
	}
}

func TestParseWebsocketLink(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseVLESS(websocketLink)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if tunnel.Transport.Type != "ws" || tunnel.Transport.Path != "/ray" {
		t.Errorf("transport = %+v", tunnel.Transport)
	}
	if tunnel.Transport.Host != "cdn.example.net" {
		t.Errorf("Host = %q", tunnel.Transport.Host)
	}
	if tunnel.TLS.Reality.Enabled {
		t.Error("a plain TLS link is not REALITY")
	}
}

func TestParsePlainLink(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseVLESS(plainLink)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if tunnel.TLS.Enabled {
		t.Error("no security parameter means no TLS")
	}
	if tunnel.Transport.Type != "" {
		t.Errorf("plain TCP needs no transport, got %q", tunnel.Transport.Type)
	}
}

// The UUID authenticates the hub to the provider, so it must not reach a revision.
func TestUUIDIsNotSerialised(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseVLESS(realityLink)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), tunnel.UUID) {
		t.Fatalf("the UUID reached the serialised form: %s", data)
	}
}

func TestParseVLESSRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]struct{ link, want string }{
		"another scheme": {
			"vmess://abc@host:443", "vless://",
		},
		"no uuid": {
			"vless://node.example.net:443", "no UUID",
		},
		"no port": {
			"vless://uuid@node.example.net", "invalid host",
		},
		// REALITY borrows a real site's certificate; without the key there is nothing
		// to verify against and without the name nothing to imitate.
		"reality without a public key": {
			"vless://uuid@node.example.net:443?security=reality&sni=example.com", "public key",
		},
		"reality without a server name": {
			"vless://uuid@node.example.net:443?security=reality&pbk=key", "server name",
		},
		"unknown security": {
			"vless://uuid@node.example.net:443?security=quantum", "unsupported security",
		},
		"unknown transport": {
			"vless://uuid@node.example.net:443?type=carrier-pigeon", "unsupported transport",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseVLESS(test.link)
			if err == nil {
				t.Fatalf("expected an error containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

// Providers add parameters the hub does not act on; refusing them would make good
// links unusable.
func TestUnknownParametersAreIgnored(t *testing.T) {
	t.Parallel()
	link := realityLink + "&alpn=h2&spx=%2F&mode=gun&extra=whatever"
	if _, err := ParseVLESS(link); err != nil {
		t.Fatalf("unknown parameters should be ignored: %v", err)
	}
}
