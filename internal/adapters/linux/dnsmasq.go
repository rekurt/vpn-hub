package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn-hub/internal/domain"
)

const (
	hubResolverUnit      = "vpn-hub-dns"
	upstreamResolverUnit = "vpn-hub-dns-upstream"
)

// RenderHubResolver builds the dnsmasq configuration that answers clients.
//
// Private zones go to the resolvers inside their own network, and every address
// dnsmasq learns for such a zone is added to that network's nftables set. That is
// what makes a name work: without the set entry the reply would resolve correctly and
// then route out of the internet path. dnsmasq 2.87 and later do this natively with
// --nftset, which is why no DNS proxy of our own is needed and no TTL bookkeeping.
func RenderHubResolver(plan domain.DNSPlan) string {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }

	line("# Managed by vpn-hub. Manual edits are reverted on the next reconcile.")
	line("no-resolv")
	line("no-hosts")
	line("bind-interfaces")
	line("listen-address=%s", plan.ListenAddress)
	// Only clients may ask; the resolver is not a service for the internet.
	line("local-service")

	for _, zone := range plan.Zones {
		for _, resolver := range zone.Resolvers {
			line("server=/%s/%s", zone.Zone, resolver)
		}
		// inet, table vpn_hub, set <name>: addresses learned for this zone start
		// routing through its tunnel from the moment they are answered.
		line("nftset=/%s/inet#vpn_hub#%s", zone.Zone, zone.Set)
	}

	if plan.UpstreamNamespace != "" {
		// Everything else goes to the resolver inside the egress namespace, so public
		// queries leave through the provider rather than from the hub's own address.
		line("server=%s", plan.UpstreamAddress)
	} else {
		for _, resolver := range plan.PublicResolvers {
			line("server=%s", resolver)
		}
	}
	return out.String()
}

// RenderUpstreamResolver builds the configuration for the instance inside the egress
// namespace, which does nothing but forward to public servers from there.
func RenderUpstreamResolver(plan domain.DNSPlan) string {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }

	line("# Managed by vpn-hub. Manual edits are reverted on the next reconcile.")
	line("no-resolv")
	line("no-hosts")
	line("bind-interfaces")
	line("listen-address=%s", plan.UpstreamAddress)
	for _, resolver := range plan.PublicResolvers {
		line("server=%s", resolver)
	}
	return out.String()
}

// Dnsmasq runs the two resolvers as transient systemd units.
//
// Transient rather than packaged units because the set of namespaces changes with
// every revision, and a unit file per namespace would need its own lifecycle to stay
// in step.
type Dnsmasq struct {
	Run       runner
	ConfigDir string
}

func (d Dnsmasq) run(ctx context.Context, name string, args ...string) (string, error) {
	return d.Run.or()(ctx, name, args...)
}

func (d Dnsmasq) configDir() string {
	if d.ConfigDir != "" {
		return d.ConfigDir
	}
	return DefaultRuntimeDir
}

func (d Dnsmasq) Apply(ctx context.Context, plan domain.DNSPlan, repopulate bool) error {
	hubConfig := filepath.Join(d.configDir(), "dnsmasq-hub.conf")
	hubChanged, err := d.write(hubConfig, RenderHubResolver(plan))
	if err != nil {
		return err
	}
	// The packet filter was rebuilt, so the sets this resolver fills are empty and
	// its cache would answer from memory without refilling them. Starting over is
	// what makes the next lookup route correctly.
	hubChanged = hubChanged || repopulate

	if plan.UpstreamNamespace != "" {
		upstreamConfig := filepath.Join(d.configDir(), "dnsmasq-upstream.conf")
		changed, err := d.write(upstreamConfig, RenderUpstreamResolver(plan))
		if err != nil {
			return err
		}
		if err := d.ensureRunning(ctx, upstreamResolverUnit, plan.UpstreamNamespace, upstreamConfig, changed || repopulate); err != nil {
			return err
		}
	} else {
		_, _ = d.run(ctx, "systemctl", "stop", upstreamResolverUnit+".service")
	}

	// The hub resolver starts last so it never forwards to an upstream that is not
	// listening yet.
	return d.ensureRunning(ctx, hubResolverUnit, "", hubConfig, hubChanged)
}

// ensureRunning starts the resolver if it is not running, and replaces it only when
// its configuration changed. Restarting on every reconcile would clear the cache
// each minute and leave a gap with no resolver at all.
func (d Dnsmasq) ensureRunning(ctx context.Context, unit, namespace, config string, changed bool) error {
	if !changed {
		if _, err := d.run(ctx, "systemctl", "is-active", "--quiet", unit+".service"); err == nil {
			return nil
		}
	}
	return d.restart(ctx, unit, namespace, config)
}

// restart replaces a transient unit, optionally inside a namespace.
func (d Dnsmasq) restart(ctx context.Context, unit, namespace, config string) error {
	// A transient unit cannot be reloaded in place, and stopping first keeps
	// systemd-run from failing on a name that is still taken.
	_, _ = d.run(ctx, "systemctl", "stop", unit+".service")

	arguments := []string{"--quiet", "--collect", "--unit=" + unit, "--property=Restart=on-failure"}
	if namespace != "" {
		arguments = append(arguments, "ip", "netns", "exec", namespace)
	}
	arguments = append(arguments, "dnsmasq", "--keep-in-foreground", "--conf-file="+config)
	_, err := d.run(ctx, "systemd-run", arguments...)
	return err
}

// write reports whether the file's contents changed.
func (d Dnsmasq) write(path, content string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create resolver config directory: %w", err)
	}
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return false, nil
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // dnsmasq reads it as nobody
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}
