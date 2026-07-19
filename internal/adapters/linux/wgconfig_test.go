package linux

import (
	"encoding/json"
	"strings"
	"testing"
)

// A configuration in the shape providers actually ship: extra keys, mixed case,
// comments and a DNS line the hub does not act on yet.
const providerConfig = `# Provider Example, location: Frankfurt
[Interface]
PrivateKey = cOFA+ItsMPRFpKt4kPsUlqUlkxHnFvJdWuBK5rXqL0Y=
Address = 10.7.0.5/32, fd00::5/128
DNS = 10.7.0.1, 10.7.0.2
MTU = 1420
Table = off

[Peer]
PublicKey = TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=
PresharedKey = 04/b7Veg9f3qvlOOl4kFPg3igGKlEIvmAwLJXYuSGQs=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = frankfurt.example.net:51820
PersistentKeepalive = 25
`

func TestParseWireGuardConfig(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseWireGuardConfig(providerConfig)
	if err != nil {
		t.Fatalf("ParseWireGuardConfig: %v", err)
	}

	if len(tunnel.Addresses) != 2 || tunnel.Addresses[0] != "10.7.0.5/32" {
		t.Errorf("Addresses = %v", tunnel.Addresses)
	}
	if tunnel.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", tunnel.MTU)
	}
	if tunnel.Peer.Endpoint != "frankfurt.example.net:51820" {
		t.Errorf("Endpoint = %q", tunnel.Peer.Endpoint)
	}
	if tunnel.Peer.Keepalive != 25 {
		t.Errorf("Keepalive = %d, want 25", tunnel.Peer.Keepalive)
	}
	if len(tunnel.Peer.AllowedIPs) != 2 {
		t.Errorf("AllowedIPs = %v", tunnel.Peer.AllowedIPs)
	}
	if len(tunnel.DNS) != 2 {
		t.Errorf("DNS = %v", tunnel.DNS)
	}
}

// Keys are secret and must not be serialised into a revision or a log line.
func TestTunnelKeysAreNotSerialised(t *testing.T) {
	t.Parallel()
	tunnel, err := ParseWireGuardConfig(providerConfig)
	if err != nil {
		t.Fatal(err)
	}
	serialised := mustMarshal(t, tunnel)
	if strings.Contains(serialised, tunnel.PrivateKey) {
		t.Error("the private key reached the serialised form")
	}
	if strings.Contains(serialised, tunnel.Peer.PresharedKey) {
		t.Error("the preshared key reached the serialised form")
	}
}

func TestParseWireGuardConfigRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]struct{ config, want string }{
		"no private key": {
			strings.Replace(providerConfig, "PrivateKey = cOFA+ItsMPRFpKt4kPsUlqUlkxHnFvJdWuBK5rXqL0Y=", "", 1),
			"Interface.PrivateKey",
		},
		"no endpoint": {
			strings.Replace(providerConfig, "Endpoint = frankfurt.example.net:51820", "", 1),
			"Peer.Endpoint",
		},
		"no address": {
			strings.Replace(providerConfig, "Address = 10.7.0.5/32, fd00::5/128", "", 1),
			"Interface.Address",
		},
		"peer key is not a key": {
			strings.Replace(providerConfig, "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=", "not-a-key", 1),
			"Peer.PublicKey",
		},
		"line is not key = value": {
			providerConfig + "\nnonsense\n", "not key = value",
		},
		// Choosing one peer silently would send traffic somewhere the operator did
		// not pick.
		"two peers": {
			providerConfig + "\n[Peer]\nPublicKey = TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=\n",
			"more than one",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseWireGuardConfig(test.config)
			if err == nil {
				t.Fatalf("expected an error containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

func mustMarshal(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
