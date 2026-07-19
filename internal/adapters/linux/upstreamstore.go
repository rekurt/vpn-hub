package linux

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
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
		if err := runtimeadapter.AtomicWrite(path+".last-known-good", previous, 0o600); err != nil {
			return fmt.Errorf("keep the previous link: %w", err)
		}
	}

	link, err := RenderVLESS(chosen)
	if err != nil {
		return err
	}
	// Atomic: the agent re-reads this file on every reconcile tick, and a plain
	// truncate-then-write exposes a window where it reads an empty or half-written
	// link and drops the upstream.
	if err := runtimeadapter.AtomicWrite(path, []byte(link+"\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Current reads back the promoted upstream, and whether a last-known-good exists
// beside it. A missing file is not an error: a subscription that never refreshed
// legitimately has neither.
func (u UpstreamFile) Current(tunnelID string) (current domain.ProxyTunnel, hasCurrent, hasPrevious bool) {
	path := filepath.Join(u.dir(), "subscriptions", tunnelID+".link")
	if content, err := os.ReadFile(path); err == nil {
		if parsed, err := ParseVLESS(strings.TrimSpace(string(content))); err == nil {
			current, hasCurrent = parsed, true
		}
	}
	if _, err := os.Stat(path + ".last-known-good"); err == nil {
		hasPrevious = true
	}
	return current, hasCurrent, hasPrevious
}

// Restore swaps the active link with the last-known-good one, so "go back" is
// itself reversible: what was active becomes the new last-known-good.
func (u UpstreamFile) Restore(tunnelID string) (domain.ProxyTunnel, error) {
	path := filepath.Join(u.dir(), "subscriptions", tunnelID+".link")
	previousPath := path + ".last-known-good"

	previous, err := os.ReadFile(previousPath)
	if err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("no last-known-good for %s: %w", tunnelID, err)
	}
	restored, err := ParseVLESS(strings.TrimSpace(string(previous)))
	if err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("the last-known-good link is unreadable: %w", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("read the active link: %w", err)
	}

	// The demoted link is written first: a crash between the two writes must leave
	// both upstreams on disk, never neither. Each write is atomic so the agent,
	// which re-reads the active link every tick, never sees a truncated one.
	if err := runtimeadapter.AtomicWrite(previousPath, current, 0o600); err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("demote the active link: %w", err)
	}
	if err := runtimeadapter.AtomicWrite(path, previous, 0o600); err != nil {
		return domain.ProxyTunnel{}, fmt.Errorf("restore the previous link: %w", err)
	}
	return restored, nil
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
