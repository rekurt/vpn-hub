package linux

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"vpn-hub/internal/domain"
)

// ParseVLESS reads a `vless://` share link.
//
// The format is a URL whose userinfo is the UUID and whose query carries the
// transport and TLS settings. Providers differ in which parameters they include, so
// unknown ones are ignored rather than rejected — refusing them would make perfectly
// good links unusable — while anything the connection cannot work without is
// required explicitly.
//
// It is a pure function, so the shapes real providers ship are tested without a
// network.
func ParseVLESS(link string) (domain.ProxyTunnel, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("parse link: %w", err)
	}
	if parsed.Scheme != "vless" {
		return domain.ProxyTunnel{}, fmt.Errorf("expected a vless:// link, got %q", parsed.Scheme)
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		return domain.ProxyTunnel{}, fmt.Errorf("the link carries no UUID")
	}

	host, rawPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("invalid host %q: %w", parsed.Host, err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return domain.ProxyTunnel{}, fmt.Errorf("invalid port %q", rawPort)
	}

	query := parsed.Query()
	tunnel := domain.ProxyTunnel{
		Protocol: "vless",
		Server:   host,
		Port:     uint16(port),
		UUID:     parsed.User.Username(),
		Flow:     query.Get("flow"),
	}

	switch security := query.Get("security"); security {
	case "reality":
		tunnel.TLS = domain.ProxyTLS{
			Enabled:     true,
			ServerName:  query.Get("sni"),
			Fingerprint: query.Get("fp"),
			Reality: domain.ProxyReality{
				Enabled:   true,
				PublicKey: query.Get("pbk"),
				ShortID:   query.Get("sid"),
			},
		}
		if tunnel.TLS.Reality.PublicKey == "" {
			return domain.ProxyTunnel{}, fmt.Errorf("a REALITY link needs a public key (pbk)")
		}
		if tunnel.TLS.ServerName == "" {
			// REALITY borrows a real site's certificate; without knowing which, the
			// handshake has nothing to imitate.
			return domain.ProxyTunnel{}, fmt.Errorf("a REALITY link needs a server name (sni)")
		}
	case "tls":
		tunnel.TLS = domain.ProxyTLS{
			Enabled:     true,
			ServerName:  query.Get("sni"),
			Fingerprint: query.Get("fp"),
		}
		if tunnel.TLS.ServerName == "" {
			tunnel.TLS.ServerName = host
		}
	case "", "none":
		// Plain TCP. Legal, and worth noticing: the traffic is recognisable.
	default:
		return domain.ProxyTunnel{}, fmt.Errorf("unsupported security %q", security)
	}

	switch transport := query.Get("type"); transport {
	case "", "tcp":
		// Nothing to record; the stream is the connection itself.
	case "ws", "httpupgrade":
		tunnel.Transport = domain.ProxyTransport{
			Type: transport,
			Path: query.Get("path"),
			Host: query.Get("host"),
		}
		if tunnel.Transport.Path == "" {
			tunnel.Transport.Path = "/"
		}
	case "grpc":
		tunnel.Transport = domain.ProxyTransport{
			Type:        "grpc",
			ServiceName: query.Get("serviceName"),
		}
	default:
		return domain.ProxyTunnel{}, fmt.Errorf("unsupported transport %q", transport)
	}

	return tunnel, nil
}
