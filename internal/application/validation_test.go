package application

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

// validateWith applies a mutation to a known-good configuration and returns the
// resulting error, so each case states only what it breaks.
func validateWith(t *testing.T, mutate func(*domain.Config)) error {
	t.Helper()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	cfg := validConfig(privateKey)
	mutate(&cfg)
	return Validate(cfg)
}

func TestValidateAcceptsTheBaseline(t *testing.T) {
	t.Parallel()
	if err := validateWith(t, func(*domain.Config) {}); err != nil {
		t.Fatalf("baseline configuration must validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*domain.Config)
		want   string
	}{
		"empty hub endpoint": {
			func(c *domain.Config) { c.Hub.Endpoint = "" }, "are required",
		},
		"endpoint without a port": {
			func(c *domain.Config) { c.Hub.Endpoint = "vpn.example.test" }, "invalid hub endpoint",
		},
		"endpoint with a non-numeric port": {
			func(c *domain.Config) { c.Hub.Endpoint = "vpn.example.test:https" }, "port must be between",
		},
		"endpoint with port zero": {
			func(c *domain.Config) { c.Hub.Endpoint = "vpn.example.test:0" }, "port must be between",
		},
		"server key that is not base64": {
			func(c *domain.Config) { c.Hub.ServerPublicKey = "server-public-key" }, "not valid base64",
		},
		"server key of the wrong length": {
			func(c *domain.Config) { c.Hub.ServerPublicKey = "YWJj" }, "decodes to 3 bytes",
		},
		"client key that is not base64": {
			func(c *domain.Config) { c.Devices[0].PublicKey = "nope!" }, "not valid base64",
		},
		"unknown AmneziaWG parameter": {
			func(c *domain.Config) { c.Hub.AWGInterface = map[string]string{"Jx": "1"} }, "unsupported parameter",
		},
		"non-numeric AmneziaWG value": {
			func(c *domain.Config) { c.Hub.AWGInterface = map[string]string{"Jc": "4\nPrivateKey = leak"} }, "must be a number",
		},
		"profile address outside the client subnet": {
			func(c *domain.Config) { c.Devices[0].Address = "192.168.1.5/32" }, "outside hub client_cidr",
		},
		"profile address that is not a host route": {
			func(c *domain.Config) { c.Devices[0].Address = "10.80.0.0/24" }, "must be a host route",
		},
		"device id with unsafe characters": {
			func(c *domain.Config) { c.Devices[0].ID = "mac book" }, "device id",
		},
		"tunnel id too long for an interface name": {
			func(c *domain.Config) {
				c.Tunnels[1].ID = "a-very-long-tunnel-id"
				c.Devices[0].Egress = "a-very-long-tunnel-id"
			}, "at most 12",
		},
		"duplicate device": {
			func(c *domain.Config) { c.Devices = append(c.Devices, c.Devices[0]) }, "duplicate device",
		},
		"duplicate tunnel": {
			func(c *domain.Config) { c.Tunnels = append(c.Tunnels, c.Tunnels[0]) }, "duplicate tunnel",
		},
		"two devices sharing an address": {
			func(c *domain.Config) {
				second := c.Devices[0]
				second.ID = "phone"
				c.Devices = append(c.Devices, second)
			}, "is shared by",
		},
		// The pre-M5 shape must say what replaced it rather than "unknown field".
		"a device still using profiles": {
			func(c *domain.Config) {
				c.Devices[0].Profiles = []domain.DeviceProfile{{ID: "macbook-xray", Egress: "xray"}}
			}, "no longer exists",
		},
		"a device whose egress is disabled": {
			func(c *domain.Config) {
				disabled := false
				c.Tunnels[1].Enabled = &disabled
			}, "which is disabled",
		},
		"egress pointing at a private-network tunnel": {
			func(c *domain.Config) { c.Devices[0].Egress = "corp" }, "is not an egress tunnel",
		},
		"egress that does not exist": {
			func(c *domain.Config) { c.Devices[0].Egress = "nowhere" }, "is not an egress tunnel",
		},
		"device excluded by the egress ACL": {
			func(c *domain.Config) { c.Tunnels[1].AllowedDevices = []string{"other"} }, "does not exist",
		},
		"wireguard tunnel with an Xray source": {
			func(c *domain.Config) { c.Tunnels[0].Source.Kind = domain.SourceXrayURI }, "must use kind config",
		},
		"unsupported tunnel type": {
			func(c *domain.Config) { c.Tunnels[0].Type = "ipsec" }, "unsupported type",
		},
		"two devices sharing a public key": {
			func(c *domain.Config) {
				second := c.Devices[0]
				second.ID = "phone"
				second.Address = "10.80.0.3/32"
				c.Devices = append(c.Devices, second)
			}, "is shared with",
		},
		"device claiming the hub's own dns_address": {
			func(c *domain.Config) { c.Devices[0].Address = "10.80.0.1/32" }, "hub's own dns_address",
		},
		"tunnel id reserved for direct": {
			func(c *domain.Config) { c.Tunnels[1].ID = domain.EgressDirect }, "reserved",
		},
		"client_cidr overlapping the egress link base": {
			func(c *domain.Config) { c.Hub.ClientCIDR = "10.90.0.0/24" }, "overlaps the egress link base",
		},
		"dns_address outside the client subnet": {
			func(c *domain.Config) { c.Hub.DNSAddress = "10.99.0.1" }, "outside client_cidr",
		},
		"endpoint host with a newline": {
			func(c *domain.Config) { c.Hub.Endpoint = "vpn.example.test\nInjected = 1:51820" }, "control character",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateWith(t, test.mutate)
			if err == nil {
				t.Fatalf("expected an error containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

// The `direct` egress is deliberately not a tunnel, so it must bypass the tunnel
// lookup rather than fail it.
func TestValidateAcceptsDirectEgress(t *testing.T) {
	t.Parallel()
	err := validateWith(t, func(c *domain.Config) {
		c.Devices[0].Egress = domain.EgressDirect
	})
	if err != nil {
		t.Fatalf("direct egress must validate: %v", err)
	}
}

// Viper lower-cases map keys while decoding, so the parameters reach validation in
// whatever case the decoder produced.
func TestValidateAcceptsLowercasedAWGParameters(t *testing.T) {
	t.Parallel()
	err := validateWith(t, func(c *domain.Config) {
		c.Hub.AWGInterface = map[string]string{"jc": "4", "h1": "12345"}
	})
	if err != nil {
		t.Fatalf("lower-cased parameters must validate: %v", err)
	}
}
