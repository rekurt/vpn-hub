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
	// Kept only so upgrades can stop the singular units before binding the new
	// per-egress addresses.
	hubResolverUnit       = "vpn-hub-dns"
	resolverUnitPrefix    = "vpn-hub-resolver-"
	upstreamResolverUnit  = resolverUnitPrefix + "public"
	clientResolverPrefix  = resolverUnitPrefix + "client-"
	publicResolverPrefix  = resolverUnitPrefix + "public-"
	privateResolverPrefix = resolverUnitPrefix + "net-"
	// legacyResolverPrefix is the space the older build generated into. Everything
	// under it is stale by construction -- the current build puts nothing there -- so
	// the sweep reaps it without consulting the plan, which is the only way to be rid
	// of a forwarder whose name is indistinguishable from a public one. The hub's own
	// unit has no trailing dash and so is never matched by it.
	legacyResolverPrefix = "vpn-hub-dns-"
)

func clientResolverUnit(egressID string) string {
	return clientResolverPrefix + safeUnitSuffix(egressID)
}

func clientResolverConfig(egressID string) string {
	return "dnsmasq-client-" + safeUnitSuffix(egressID) + ".conf"
}

func publicResolverUnit(egressID string) string {
	return publicResolverPrefix + safeUnitSuffix(egressID)
}

func publicResolverConfig(egressID string) string {
	return "dnsmasq-public-" + safeUnitSuffix(egressID) + ".conf"
}

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

// RenderClientResolver builds the main-namespace configuration for one egress.
//
// Private zones go to the resolvers inside their own network, and every address
// dnsmasq learns for such a zone is added to that network's nftables set. That is
// what makes a name work: without the set entry the reply would resolve correctly and
// then route out of the internet path. dnsmasq 2.87 and later do this natively with
// --nftset, which is why no DNS proxy of our own is needed and no TTL bookkeeping.
func RenderClientResolver(plan domain.DNSPlan, resolver domain.DNSEgressResolver) string {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }

	line("# Managed by vpn-hub. Manual edits are reverted on the next reconcile.")
	line("no-resolv")
	line("no-hosts")
	line("bind-interfaces")
	line("listen-address=%s", resolver.HubAddress)
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

	if resolver.Namespace != "" {
		line("server=%s", resolver.NamespaceAddress)
	} else {
		for _, upstream := range resolver.PublicResolvers {
			line("server=%s", upstream)
		}
	}
	return out.String()
}

// RenderPublicResolver builds the public forwarder inside an egress namespace.
func RenderPublicResolver(resolver domain.DNSEgressResolver) string {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }

	line("# Managed by vpn-hub. Manual edits are reverted on the next reconcile.")
	line("no-resolv")
	line("no-hosts")
	line("bind-interfaces")
	line("listen-address=%s", resolver.NamespaceAddress)
	for _, upstream := range resolver.PublicResolvers {
		line("server=%s", upstream)
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
	// These fixed-name units belonged to the singular resolver model. They are not in
	// either generated prefix and must release their addresses before replacements bind.
	_, _ = d.run(ctx, "systemctl", "stop", hubResolverUnit+".service")
	_, _ = d.run(ctx, "systemctl", "stop", upstreamResolverUnit+".service")

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

	// Namespace forwarders start before the main resolvers that depend on them.
	for _, resolver := range plan.EgressResolvers {
		if resolver.Namespace == "" {
			continue
		}
		config := filepath.Join(d.configDir(), publicResolverConfig(resolver.EgressID))
		changed, err := d.write(config, RenderPublicResolver(resolver))
		if err != nil {
			return err
		}
		if err := d.ensureRunning(ctx, publicResolverUnit(resolver.EgressID), resolver.Namespace, config, changed || repopulate); err != nil {
			return err
		}
	}

	for _, resolver := range plan.EgressResolvers {
		config := filepath.Join(d.configDir(), clientResolverConfig(resolver.EgressID))
		changed, err := d.write(config, RenderClientResolver(plan, resolver))
		if err != nil {
			return err
		}
		if err := d.ensureRunning(ctx, clientResolverUnit(resolver.EgressID), "", config, changed || repopulate); err != nil {
			return err
		}
	}
	return stale
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
	wanted := make(map[string]struct{}, len(plan.PrivateResolvers)+len(plan.EgressResolvers)*2)
	for _, resolver := range plan.PrivateResolvers {
		wanted[privateResolverUnit(resolver.TunnelID)] = struct{}{}
	}
	for _, resolver := range plan.EgressResolvers {
		wanted[clientResolverUnit(resolver.EgressID)] = struct{}{}
		if resolver.Namespace != "" {
			wanted[publicResolverUnit(resolver.EgressID)] = struct{}{}
		}
	}

	legacy, legacyErr := d.listResolverUnits(ctx, legacyResolverPrefix)
	for _, unit := range legacy {
		_, _ = d.run(ctx, "systemctl", "stop", unit+".service")
	}

	type generatedSpace struct {
		prefix string
		config func(string) string
	}
	spaces := []generatedSpace{
		{privateResolverPrefix, privateResolverConfig},
		{publicResolverPrefix, publicResolverConfig},
		{clientResolverPrefix, clientResolverConfig},
	}
	errs := []error{legacyErr}
	for _, space := range spaces {
		units, err := d.listResolverUnits(ctx, space.prefix)
		errs = append(errs, err)
		for _, unit := range units {
			if _, keep := wanted[unit]; keep {
				continue
			}
			_, _ = d.run(ctx, "systemctl", "stop", unit+".service")
			suffix, _ := strings.CutPrefix(unit, space.prefix)
			_ = os.Remove(filepath.Join(d.configDir(), space.config(suffix)))
		}
	}
	return errors.Join(errs...)
}

// listResolverUnits asks systemd which resolver units exist under a prefix.
//
// A failure is reported rather than read as "there are none". Treating it as an empty
// host is what would let a withdrawn network's forwarder survive every later
// reconcile in silence, since each pass would conclude afresh that there was nothing
// to reap.
func (d Dnsmasq) listResolverUnits(ctx context.Context, prefix string) ([]string, error) {
	output, err := d.run(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend",
		prefix+"*.service")
	if err != nil {
		return nil, fmt.Errorf("list %s* units: %w", prefix, err)
	}
	return unitNames(output, prefix), nil
}

// unitNames reads unit names out of `systemctl list-units` output.
//
// The name is found by its prefix rather than taken from a fixed column: a unit in a
// failed state is printed with a leading bullet, which shifts every column right by
// one, and a resolver that lost its namespace is exactly the case where that happens.
func unitNames(output, prefix string) []string {
	var units []string
	for _, line := range strings.Split(output, "\n") {
		for _, field := range strings.Fields(line) {
			name, isService := strings.CutSuffix(field, ".service")
			if isService && strings.HasPrefix(name, prefix) {
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
