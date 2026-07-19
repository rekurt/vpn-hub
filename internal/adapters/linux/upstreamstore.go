package linux

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"vpn-hub/internal/domain"
)

// UpstreamFile writes a chosen candidate back as a share link, in the same file the
// reconciler reads.
//
// The previous link is kept beside it. A subscription that starts offering only
// broken nodes should cost you the update, not the connection you had; keeping the
// last working one makes that recoverable by hand as well as automatically.
type UpstreamFile struct {
	Dir string
}

func (u UpstreamFile) dir() string {
	if u.Dir != "" {
		return u.Dir
	}
	return "/etc/vpn-hub"
}

func (u UpstreamFile) Write(_ context.Context, tunnel domain.Tunnel, chosen domain.ProxyTunnel) error {
	path := filepath.Join(u.dir(), "subscriptions", tunnel.ID+".link")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create subscription directory: %w", err)
	}

	if previous, err := os.ReadFile(path); err == nil {
		// Written before the replacement, so a crash midway leaves the old link
		// recoverable rather than nothing at all.
		if err := os.WriteFile(path+".last-known-good", previous, 0o600); err != nil {
			return fmt.Errorf("keep the previous link: %w", err)
		}
	}

	link, err := RenderVLESS(chosen)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(link+"\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// RenderVLESS turns a parsed tunnel back into a share link, so what the hub stores
// stays in the format an operator can read and paste elsewhere.
func RenderVLESS(tunnel domain.ProxyTunnel) (string, error) {
	if tunnel.Server == "" || tunnel.Port == 0 || tunnel.UUID == "" {
		return "", fmt.Errorf("the tunnel is missing a server, port or UUID")
	}

	query := url.Values{}
	query.Set("encryption", "none")
	if tunnel.Flow != "" {
		query.Set("flow", tunnel.Flow)
	}
	switch {
	case tunnel.TLS.Reality.Enabled:
		query.Set("security", "reality")
		query.Set("pbk", tunnel.TLS.Reality.PublicKey)
		if tunnel.TLS.Reality.ShortID != "" {
			query.Set("sid", tunnel.TLS.Reality.ShortID)
		}
	case tunnel.TLS.Enabled:
		query.Set("security", "tls")
	}
	if tunnel.TLS.ServerName != "" {
		query.Set("sni", tunnel.TLS.ServerName)
	}
	if tunnel.TLS.Fingerprint != "" {
		query.Set("fp", tunnel.TLS.Fingerprint)
	}

	switch tunnel.Transport.Type {
	case "":
		query.Set("type", "tcp")
	case "grpc":
		query.Set("type", "grpc")
		query.Set("serviceName", tunnel.Transport.ServiceName)
	default:
		query.Set("type", tunnel.Transport.Type)
		query.Set("path", tunnel.Transport.Path)
		if tunnel.Transport.Host != "" {
			query.Set("host", tunnel.Transport.Host)
		}
	}

	link := url.URL{
		Scheme:   "vless",
		User:     url.User(tunnel.UUID),
		Host:     fmt.Sprintf("%s:%d", tunnel.Server, tunnel.Port),
		RawQuery: query.Encode(),
	}
	return link.String(), nil
}
