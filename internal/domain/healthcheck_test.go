package domain

import "testing"

// These values reach a command this process runs as root. The test names the exact
// payloads that worked before validation existed, so a regression is recognisable
// rather than merely red.
func TestProbeTargetsThatWouldRunCommands(t *testing.T) {
	t.Parallel()

	cases := map[string]HealthCheck{
		// net.SplitHostPort accepts anything at all inside brackets, so it is a
		// parser and never was a validator.
		"bracketed shell metacharacters": {TCPAddress: "[; id ;]:443"},
		"command substitution":           {TCPAddress: "$(id):443"},
		"backticks":                      {TCPAddress: "`id`:443"},
		"newline in the host":            {TCPAddress: "example.test\nid:443"},
		"port is not a number":           {TCPAddress: "example.test:$(id)"},
		"port zero":                      {TCPAddress: "example.test:0"},
		// A leading dash turns the value into a flag for whatever runs it.
		"host reads as a flag":       {DNSName: "-oProxyCommand=id"},
		"url host reads as a flag":   {HTTPSURL: "https://-oProxyCommand=id/"},
		"probe that proves nothing":  {HTTPSURL: "http://example.test/"},
		"scheme that is not a fetch": {HTTPSURL: "file:///etc/shadow"},
	}

	for name, check := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := check.Validate(); err == nil {
				t.Fatalf("%+v was accepted", check)
			}
		})
	}
}

func TestOrdinaryProbeTargetsAreAccepted(t *testing.T) {
	t.Parallel()

	cases := map[string]HealthCheck{
		"empty means no probe": {},
		"address and port":     {TCPAddress: "10.20.0.53:53"},
		"ipv6 in brackets":     {TCPAddress: "[2001:db8::1]:53"},
		"host and port":        {TCPAddress: "gateway.corp.internal:443"},
		"https url":            {HTTPSURL: "https://1.1.1.1/cdn-cgi/trace"},
		"https url with path":  {HTTPSURL: "https://intranet.corp.internal/health?deep=1"},
		"dns name":             {DNSName: "gateway.corp.internal"},
		"underscored label":    {DNSName: "_service.corp.internal"},
		"all three at once": {
			TCPAddress: "10.20.0.53:53",
			HTTPSURL:   "https://intranet.corp.internal/",
			DNSName:    "intranet.corp.internal",
		},
	}

	for name, check := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := check.Validate(); err != nil {
				t.Fatalf("%+v was rejected: %v", check, err)
			}
		})
	}
}

func TestDNSZonesThatWouldWriteTheirOwnDirectives(t *testing.T) {
	t.Parallel()

	// The first is the one that matters: dnsmasq's address=/#/ answers every name
	// that exists, so a zone able to smuggle a newline owns all of DNS.
	for _, zone := range []string{
		"corp.internal\naddress=/#/198.51.100.7",
		"corp.internal\r\nserver=/#/198.51.100.7",
		"corp internal",
		"corp.internal/../etc",
		"#",
		"",
		"corp..internal",
	} {
		if err := ValidateDNSZone(zone); err == nil {
			t.Errorf("zone %q was accepted", zone)
		}
	}

	for _, zone := range []string{"corp.internal", "a-b.example", "_tcp.corp.internal", "internal"} {
		if err := ValidateDNSZone(zone); err != nil {
			t.Errorf("zone %q was rejected: %v", zone, err)
		}
	}
}
