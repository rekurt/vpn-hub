package linux

import (
	"encoding/json"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func decode(t *testing.T, config string) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatalf("the rendered configuration is not valid JSON: %v\n%s", err, config)
	}
	return parsed
}

func renderFrom(t *testing.T, link string) (string, map[string]any) {
	t.Helper()
	tunnel, err := ParseVLESS(link)
	if err != nil {
		t.Fatal(err)
	}
	config, err := RenderSingBoxConfig(tunnel)
	if err != nil {
		t.Fatalf("RenderSingBoxConfig: %v", err)
	}
	return config, decode(t, config)
}

func TestRenderedConfigCarriesTheRealitySettings(t *testing.T) {
	t.Parallel()
	config, _ := renderFrom(t, realityLink)
	for _, wanted := range []string{
		`"type": "vless"`, `"server": "node.example.net"`, `"server_port": 443`,
		`"flow": "xtls-rprx-vision"`, `"public_key"`, `"short_id": "0123abcd"`,
		`"server_name": "www.microsoft.com"`, `"fingerprint": "chrome"`,
	} {
		if !strings.Contains(config, wanted) {
			t.Errorf("missing %q:\n%s", wanted, config)
		}
	}
}

// The namespace's default route points at the tun device sing-box serves, so its own
// connections need a way around it. Binding to the interface is not enough -- that
// sets the socket's device without giving it a route, and the connection fails with
// "no route to host". A mark lets a rule inside the namespace divert them.
func TestOutboundIsMarkedSoItDoesNotLoop(t *testing.T) {
	t.Parallel()
	config, _ := renderFrom(t, realityLink)
	if !strings.Contains(config, `"routing_mark": 2`) {
		t.Errorf("the outbound must be marked:\n%s", config)
	}
}

// The hub owns routing; sing-box installing its own would fight the policy rules the
// reconciler places.
func TestSingBoxDoesNotManageRouting(t *testing.T) {
	t.Parallel()
	config, parsed := renderFrom(t, realityLink)
	if !strings.Contains(config, `"auto_route": false`) {
		t.Error("auto_route must stay off")
	}
	route, _ := parsed["route"].(map[string]any)
	if route == nil || route["auto_detect_interface"] != false {
		t.Errorf("auto_detect_interface must be off inside a namespace: %v", route)
	}
}

func TestWebsocketTransportIsRendered(t *testing.T) {
	t.Parallel()
	config, _ := renderFrom(t, websocketLink)
	for _, wanted := range []string{`"type": "ws"`, `"path": "/ray"`, `"Host": "cdn.example.net"`} {
		if !strings.Contains(config, wanted) {
			t.Errorf("missing %q:\n%s", wanted, config)
		}
	}
}

func TestPlainLinkRendersWithoutTLS(t *testing.T) {
	t.Parallel()
	config, _ := renderFrom(t, plainLink)
	if strings.Contains(config, `"tls"`) {
		t.Errorf("a link without security must not claim TLS:\n%s", config)
	}
}

func TestRenderRejectsAnIncompleteTunnel(t *testing.T) {
	t.Parallel()
	for name, tunnel := range map[string]domain.ProxyTunnel{
		"no protocol": {Server: "host", Port: 443, UUID: "u"},
		"no server":   {Protocol: "vless", Port: 443, UUID: "u"},
		"no uuid":     {Protocol: "vless", Server: "host", Port: 443},
		"bad transport": {
			Protocol: "vless", Server: "host", Port: 443, UUID: "u",
			Transport: domain.ProxyTransport{Type: "smoke-signal"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := RenderSingBoxConfig(tunnel); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
