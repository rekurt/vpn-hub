package linux

import (
	"context"
	"testing"
)

// Captured from the lab host.
const defaultRouteJSON = `[{"dst":"default","gateway":"64.225.96.1","dev":"eth0","protocol":"static","flags":[]}]`

func TestParseDefaultRoute(t *testing.T) {
	t.Parallel()
	device, err := ParseDefaultRoute(defaultRouteJSON)
	if err != nil {
		t.Fatalf("ParseDefaultRoute: %v", err)
	}
	if device != "eth0" {
		t.Fatalf("device = %q, want eth0", device)
	}
}

// A host with no default route must be an explicit failure: silently rendering a
// firewall with an empty interface name would produce rules that match nothing.
func TestParseDefaultRouteRequiresARoute(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"empty list":  `[]`,
		"no device":   `[{"dst":"default","gateway":"10.0.0.1"}]`,
		"not JSON":    `Device "x" does not exist.`,
		"wrong shape": `{"dst":"default"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDefaultRoute(input); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestUplinkInterfaceUsesMachineReadableOutput(t *testing.T) {
	t.Parallel()
	host := &fakeHost{replies: map[string]string{
		"ip -j route show default": defaultRouteJSON,
	}}
	device, err := NetConf{Run: host.run}.UplinkInterface(context.Background())
	if err != nil {
		t.Fatalf("UplinkInterface: %v", err)
	}
	if device != "eth0" {
		t.Fatalf("device = %q, want eth0", device)
	}
}
