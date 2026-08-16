package linux

import (
	"context"
	"encoding/json"
	"fmt"
)

// route mirrors the fields of `ip -j route show` that matter here.
type route struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway"`
	Device      string `json:"dev"`
}

// ParseDefaultRoute extracts the uplink interface from `ip -j route show default`.
//
// The interface cannot come from configuration: it is whatever the host happens to
// call its default path to the internet, and the firewall policy has to name it in
// the masquerade and forward rules.
func ParseDefaultRoute(output string) (string, error) {
	var routes []route
	if err := json.Unmarshal([]byte(output), &routes); err != nil {
		return "", fmt.Errorf("decode route output: %w", err)
	}
	for _, candidate := range routes {
		if candidate.Device != "" {
			return candidate.Device, nil
		}
	}
	return "", fmt.Errorf("no default route: the host has no path to the internet")
}

// NetConf answers questions about the host's own networking.
type NetConf struct {
	Run runner
}

func (n NetConf) run(ctx context.Context, name string, args ...string) (string, error) {
	return n.Run.or()(ctx, name, args...)
}

func (n NetConf) UplinkInterface(ctx context.Context) (string, error) {
	output, err := n.run(ctx, "ip", "-j", "route", "show", "default")
	if err != nil {
		return "", err
	}
	return ParseDefaultRoute(output)
}
