package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpn-hub/internal/domain"
)

const (
	hubResolverUnit = "vpn-hub-dns"
	// upstreamResolverUnit carries the public forwarder. "public" rather than
	// "upstream", which the domain calls it and its configuration file still does,
	// because this name shares a prefix with the tunnel-derived ones: a tunnel may be
	// called "upstream", and under the older build its forwarder claimed this very
	// unit. A name any other path could have started cannot be reasoned about, and
	// the sweep below has to exempt this one from reaping.
	upstreamResolverUnit = "vpn-hub-dns-public"
	// resolverUnitPrefix matches every resolver that runs inside a namespace, and the
	// stale sweep enumerates by it rather than by privateResolverPrefix. The wider
	// pattern is what reaps a forwarder left by an earlier build under a name this
	// one no longer generates: it holds the very address its replacement is about to
	// bind, and dnsmasq cannot bind an address twice. The hub's own unit has no
	// trailing dash, so it is never matched.
	resolverUnitPrefix = "vpn-hub-dns-"
	// privateResolverPrefix names the per-network forwarders. The "private-" segment
	// is not decoration: only "direct" is a reserved tunnel id, so a tunnel called
	// "upstream" is accepted, and without the segment its forwarder would claim the
	// unit name upstreamResolverUnit already uses. The two resolvers would then evict
	// each other from one transient unit on every reconcile, and whichever started
	// last would answer for both -- private zones out of the public forwarder, or
	// public queries into a corporate network.
	privateResolverPrefix = resolverUnitPrefix + "private-"
)

// privateResolverUnit and privateResolverConfig name a network's forwarder.
//
// Both the DNS adapter that starts it and the egress adapter that must stop it
// before deleting its namespace go through these, because a unit started under one
// spelling and stopped under another is a process nothing ever reaps.
func privateResolverUnit(tunnelID string) string {
	return privateResolverPrefix + safeUnitSuffix(tunnelID)
}

func privateResolverConfig(tunnelID string) string {
	return "dnsmasq-private-" + safeUnitSuffix(tunnelID) + ".conf"
}

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
		resolvers := zone.Resolvers
		if zone.ForwardAddress != "" {
			resolvers = []string{zone.ForwardAddress}
		}
		for _, resolver := range resolvers {
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

// RenderPrivateResolver builds a resolver that runs inside a private-network
// namespace and forwards that network's zones to the DNS servers reachable there.
func RenderPrivateResolver(resolver domain.DNSPrivateResolver) string {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }

	line("# Managed by vpn-hub. Manual edits are reverted on the next reconcile.")
	line("no-resolv")
	line("no-hosts")
	line("bind-interfaces")
	line("listen-address=%s", resolver.Address)
	for _, upstream := range resolver.Resolvers {
		line("server=%s", upstream)
	}
	return out.String()
}

// Dnsmasq runs the resolvers as transient systemd units.
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
	// Reaping comes before starting, not after: a forwarder this revision dropped
	// still holds its namespace's address, and one it renamed holds the address its
	// replacement is about to ask for. Started first, the replacement would fail to
	// bind and spend its restart backoff waiting for the sweep that follows it.
	//
	// The failure is collected rather than returned. Reaping is housekeeping, and
	// giving up here would skip everything below -- clients would lose DNS entirely
	// because one bookkeeping command failed. The error still surfaces, once the
	// resolvers are serving.
	stale := d.forgetStaleResolvers(ctx, plan)

	// Private-zone resolvers must start before the hub resolver, because the hub
	// forwards matching zones to them.
	for _, resolver := range plan.PrivateResolvers {
		config := filepath.Join(d.configDir(), privateResolverConfig(resolver.TunnelID))
		changed, err := d.write(config, RenderPrivateResolver(resolver))
		if err != nil {
			return err
		}
		unit := privateResolverUnit(resolver.TunnelID)
		if err := d.ensureRunning(ctx, unit, resolver.Namespace, config, changed || repopulate); err != nil {
			return err
		}
	}

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
	return errors.Join(stale, d.ensureRunning(ctx, hubResolverUnit, "", hubConfig, hubChanged))
}

// forgetStaleResolvers stops the namespace resolvers this revision no longer names.
//
// A tunnel that merely drops its dns_zones keeps its namespace, so the egress adapter
// never visits it, while the loop below no longer names it either. Nothing else would
// ever stop its forwarder: the process would go on holding the namespace's veth
// address for as long as the hub runs, answering from a configuration no revision
// describes any more.
//
// systemd is asked what exists rather than the configuration directory being listed.
// What has to be stopped is a process, and only systemd knows which ones an earlier
// pass left behind -- a config file proves a forwarder was once written, not that it
// is still running, and one started before the directory was reconfigured has no file
// to be found by at all.
func (d Dnsmasq) forgetStaleResolvers(ctx context.Context, plan domain.DNSPlan) error {
	wanted := make(map[string]struct{}, len(plan.PrivateResolvers)+1)
	for _, resolver := range plan.PrivateResolvers {
		wanted[privateResolverUnit(resolver.TunnelID)] = struct{}{}
	}
	// The public forwarder is spared because it has an owner already: Apply starts it
	// or stops it by name, according to whether a namespace carries the internet. Two
	// owners for one unit is how it ends up stopped in the pass that started it.
	//
	// The exemption holds only because no other path can have started this unit. It
	// did not hold for the name the public forwarder used before: a tunnel called
	// "upstream" claimed that one too, and on a host upgraded from that build the
	// process behind it may be either resolver. Exempting it there would keep the
	// private forwarder alive under the public forwarder's name -- its replacement
	// could not bind the address, and because the public configuration is unchanged
	// and the unit looks active, public queries would go on reaching the corporate
	// resolver. Under the current name that unit is unclaimed, so the sweep reaps it.
	wanted[upstreamResolverUnit] = struct{}{}

	output, err := d.run(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend",
		resolverUnitPrefix+"*.service")
	if err != nil {
		// Reported rather than read as "there are none". Treating the failure as an
		// empty host is what would let a withdrawn network's forwarder survive every
		// later reconcile in silence, since each pass would conclude afresh that
		// there was nothing to reap.
		return fmt.Errorf("list resolver units: %w", err)
	}
	for _, unit := range resolverUnits(output) {
		if _, keep := wanted[unit]; keep {
			continue
		}
		_, _ = d.run(ctx, "systemctl", "stop", unit+".service")
		// Only a unit carrying the private prefix names a configuration of its own.
		// A leftover under the older name shares its file with the forwarder that
		// replaced it, so deleting by that name would pull the configuration out from
		// under a resolver that is running and wanted.
		if tunnelID, private := strings.CutPrefix(unit, privateResolverPrefix); private {
			// The configuration goes with the process it described. Left behind, it
			// would accumulate in the runtime directory across every revision that
			// ever named the network, and read as a resolver still meant to exist.
			_ = os.Remove(filepath.Join(d.configDir(), privateResolverConfig(tunnelID)))
		}
	}
	return nil
}

// resolverUnits reads unit names out of `systemctl list-units` output.
//
// The name is found by its prefix rather than taken from a fixed column: a unit in a
// failed state is printed with a leading bullet, which shifts every column right by
// one, and a resolver that lost its namespace is exactly the case where that happens.
func resolverUnits(output string) []string {
	var units []string
	for _, line := range strings.Split(output, "\n") {
		for _, field := range strings.Fields(line) {
			name, isService := strings.CutSuffix(field, ".service")
			if isService && strings.HasPrefix(name, resolverUnitPrefix) {
				units = append(units, name)
			}
		}
	}
	return units
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

func safeUnitSuffix(value string) string {
	result := strings.Builder{}
	for _, symbol := range value {
		switch {
		case symbol >= 'a' && symbol <= 'z':
			result.WriteRune(symbol)
		case symbol >= 'A' && symbol <= 'Z':
			result.WriteRune(symbol)
		case symbol >= '0' && symbol <= '9':
			result.WriteRune(symbol)
		case symbol == '-' || symbol == '_':
			result.WriteRune(symbol)
		default:
			result.WriteRune('-')
		}
	}
	if result.Len() == 0 {
		return "private"
	}
	return result.String()
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
