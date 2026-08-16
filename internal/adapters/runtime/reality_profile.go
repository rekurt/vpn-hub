package runtime

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"vpn-hub/internal/domain"
)

// RealityProfileRenderer builds what a client application imports for the TCP/443
// fallback: a vless:// link, in the same shape the hub already parses when a
// provider hands it one.
type RealityProfileRenderer struct{}

// Link renders the fallback credential for one device.
//
// The private key stays on the hub: the credential a device gets is its derived
// UUID, and the link carries only the public half of the handshake material.
func (RealityProfileRenderer) Link(hub domain.Hub, deviceID, uuid, publicKey string) (string, error) {
	if !hub.Fallback.Reality.Enabled {
		return "", fmt.Errorf("the REALITY fallback is not enabled")
	}
	if uuid == "" || publicKey == "" {
		return "", fmt.Errorf("a REALITY link needs a credential and a public key")
	}
	host, _, err := net.SplitHostPort(hub.Endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid hub endpoint %q: %w", hub.Endpoint, err)
	}

	query := url.Values{}
	query.Set("security", "reality")
	query.Set("encryption", "none")
	query.Set("type", "tcp")
	// Must match the server's users[].flow: a mismatch handshakes and then carries
	// nothing, which reads to the operator as "connects but no internet".
	query.Set("flow", "xtls-rprx-vision")
	query.Set("sni", hub.Fallback.Reality.ServerName)
	query.Set("fp", "chrome")
	query.Set("pbk", publicKey)
	query.Set("sid", domain.RealityShortID(publicKey))

	link := url.URL{
		Scheme:   "vless",
		User:     url.User(uuid),
		Host:     net.JoinHostPort(host, fmt.Sprint(domain.RealityPort)),
		RawQuery: query.Encode(),
		Fragment: "vpn-hub-" + deviceID,
	}
	return link.String(), nil
}

// AltPortProfile re-renders a device's ordinary profile against UDP/443.
//
// The hub redirects that port to its ingress, so the profile is the same one with
// a different endpoint port -- which is exactly why it is rendered here rather than
// left to the operator to edit by hand on a phone.
func AltPortProfile(hub domain.Hub, address, privateKey string) (string, error) {
	if !hub.Fallback.UDP443 {
		return "", fmt.Errorf("the UDP/443 fallback is not enabled")
	}
	host, _, err := net.SplitHostPort(hub.Endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid hub endpoint %q: %w", hub.Endpoint, err)
	}
	alternate := hub
	alternate.Endpoint = net.JoinHostPort(host, fmt.Sprint(domain.RealityPort))
	return AmneziaProfileRenderer{}.Render(alternate, address, privateKey)
}

// RealityProfileName is what the fallback profile is called when it is delivered as
// a file, kept beside the ordinary one rather than replacing it.
func RealityProfileName(deviceID string) string {
	return strings.ReplaceAll(deviceID, " ", "-") + "-443.conf"
}
