package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// A revision is written to disk and read back by anything that can open the state
// directory, so credentials must not survive into it.
func TestCredentialBearingSourcesAreRedacted(t *testing.T) {
	t.Parallel()
	secret := "vless://7a1f8c2e-0000-0000-0000-000000000000@provider.example:443"

	for _, kind := range []SourceKind{SourceXrayURI, SourceSubscription} {
		serialised := mustMarshal(t, Tunnel{ID: "x", Source: TunnelSource{Kind: kind, Value: secret}})
		if strings.Contains(serialised, "7a1f8c2e") {
			t.Errorf("%s: the credential survived into the revision: %s", kind, serialised)
		}
		if !strings.Contains(serialised, "[redacted]") {
			t.Errorf("%s: expected the value to be marked as redacted, got %s", kind, serialised)
		}
		// The kind must stay, or a reader cannot tell what was hidden.
		if !strings.Contains(serialised, string(kind)) {
			t.Errorf("%s: the source kind was lost", kind)
		}
	}
}

// A config source names a file on the host. It carries nothing secret and is worth
// seeing, since it is what the agent will try to open.
func TestFileSourcesAreNotRedacted(t *testing.T) {
	t.Parallel()
	serialised := mustMarshal(t, Tunnel{
		ID:     "corp",
		Source: TunnelSource{Kind: SourceConfig, Value: "corp-wg.conf"},
	})
	if !strings.Contains(serialised, "corp-wg.conf") {
		t.Fatalf("the file name should be visible: %s", serialised)
	}
}

func TestDeviceKeysNeverSerialise(t *testing.T) {
	t.Parallel()
	private, public, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serialised := mustMarshal(t, Device{
		ID: "laptop", Address: "10.80.0.2/32",
		PublicKey: public, Egress: EgressDirect,
		// The pre-M5 shape is still decoded so validation can name its replacement;
		// it must not reach the revision.
		Profiles: []DeviceProfile{{ID: "laptop-direct", ClientPrivateKey: private}},
	})
	if strings.Contains(serialised, private) {
		t.Fatal("a device private key reached the serialised form")
	}
	if !strings.Contains(serialised, public) {
		t.Fatal("the public key should be present: the hub needs it")
	}
}

// The upstream identity is the hub's credential towards a provider.
func TestUpstreamKeysNeverSerialise(t *testing.T) {
	t.Parallel()
	serialised := mustMarshal(t, WireGuardTunnel{
		PrivateKey: "cOFA+ItsMPRFpKt4kPsUlqUlkxHnFvJdWuBK5rXqL0Y=",
		Addresses:  []string{"10.7.0.5/32"},
		Peer: WireGuardPeer{
			PublicKey:    "TE5crMJPBmCr2bF/uSbHqAlTAHKQwLKMs0RQxfQ0LU4=",
			PresharedKey: "04/b7Veg9f3qvlOOl4kFPg3igGKlEIvmAwLJXYuSGQs=",
			Endpoint:     "provider.example:51820",
		},
	})
	for _, secret := range []string{"cOFA+Its", "04/b7Veg"} {
		if strings.Contains(serialised, secret) {
			t.Errorf("a secret reached the serialised form: %s", serialised)
		}
	}
}

func TestProxyOriginServerNeverSerialises(t *testing.T) {
	t.Parallel()
	serialised := mustMarshal(t, ProxyTunnel{
		Server:       "1.1.1.1",
		OriginServer: "provider.example",
	})
	if strings.Contains(serialised, "provider.example") {
		t.Fatalf("the in-memory origin reached the serialised form: %s", serialised)
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
