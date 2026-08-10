package application

import (
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func fallbackConfig(t *testing.T, fallback domain.IngressFallback) domain.Config {
	t.Helper()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	cfg.Hub.Fallback = fallback
	return cfg
}

func TestValidateFallback(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fallback domain.IngressFallback
		endpoint string
		wantErr  string
	}{
		"absent is valid": {},
		"udp443 alone is valid": {
			fallback: domain.IngressFallback{UDP443: true},
		},
		"reality with a server name is valid": {
			fallback: domain.IngressFallback{
				Reality: domain.RealityFallback{Enabled: true, ServerName: "www.example.com"},
			},
		},
		"a stale server name with reality off is tolerated": {
			fallback: domain.IngressFallback{
				Reality: domain.RealityFallback{ServerName: "www.example.com"},
			},
		},
		"reality without a server name is refused": {
			fallback: domain.IngressFallback{Reality: domain.RealityFallback{Enabled: true}},
			wantErr:  "server_name is required",
		},
		"a server name that is not a hostname is refused": {
			fallback: domain.IngressFallback{
				Reality: domain.RealityFallback{Enabled: true, ServerName: "https://www.example.com/"},
			},
			wantErr: "not a bare hostname",
		},
		"a single-label server name is refused": {
			fallback: domain.IngressFallback{
				Reality: domain.RealityFallback{Enabled: true, ServerName: "localhost"},
			},
			wantErr: "needs at least one dot",
		},
		"mimicking the hub itself is refused": {
			fallback: domain.IngressFallback{
				Reality: domain.RealityFallback{Enabled: true, ServerName: "vpn.example.test"},
			},
			wantErr: "the hub's own endpoint",
		},
		"udp443 is refused when the hub already listens on 443": {
			fallback: domain.IngressFallback{UDP443: true},
			endpoint: "vpn.example.test:443",
			wantErr:  "pointless",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := fallbackConfig(t, test.fallback)
			if test.endpoint != "" {
				cfg.Hub.Endpoint = test.endpoint
			}

			err := Validate(cfg)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("valid configuration was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a refusal mentioning %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error %q does not mention %q", err, test.wantErr)
			}
		})
	}
}

// The plan is what the renderer sees, so the gate has to reach it: a fallback
// configured but absent from the plan would open no port, and one present without
// being configured would open 443 on every hub.
func TestFirewallPlanCarriesTheFallbackGate(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(privateKey)
	state, err := Service{}.BuildDesiredState(cfg)
	if err != nil {
		t.Fatal(err)
	}

	off, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if off.AltUDP443 || off.RealityPort != 0 {
		t.Fatalf("the fallback leaked into a plan that did not ask for it: %+v", off)
	}

	state.Hub.Fallback = domain.IngressFallback{
		UDP443:  true,
		Reality: domain.RealityFallback{Enabled: true, ServerName: "www.example.com"},
	}
	on, err := BuildFirewallPlan(state, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if !on.AltUDP443 {
		t.Error("udp443 did not reach the plan")
	}
	if on.RealityPort != domain.RealityPort {
		t.Errorf("reality port = %d, want %d", on.RealityPort, domain.RealityPort)
	}
}
