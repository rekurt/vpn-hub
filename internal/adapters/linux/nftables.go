package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"vpn-hub/internal/domain"
)

// internalSetName names the address set of one private network. Identifier safety
// comes from validation, which restricts tunnel IDs to a charset nftables accepts.
func internalSetName(tunnelID string) string {
	return "internal_" + strings.ReplaceAll(tunnelID, "-", "_")
}

// Fingerprint identifies a firewall plan by its content.
//
// It is deliberately computed from the plan rather than from the rendered text: the
// rendering is what the fingerprint is embedded in, so hashing the output would have
// to hash around its own marker.
func Fingerprint(plan domain.FirewallPlan) string {
	payload, err := json.Marshal(plan)
	if err != nil {
		// FirewallPlan holds only strings, numbers and slices of them.
		panic("firewall plan is not serialisable: " + err.Error())
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])[:16]
}

// RenderRuleset formats a firewall plan as an nftables script.
//
// It is a pure function so the policy can be reviewed and diffed without touching a
// host, which is also what makes the golden tests possible on any platform.
func RenderRuleset(plan domain.FirewallPlan) string {
	var out strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&out, format+"\n", args...)
	}

	line("# Managed by vpn-hub. Manual edits are reverted on the next reconcile.")
	line("")
	line("# Creating the table before deleting it makes the definition below an atomic")
	line("# replacement of this table alone, leaving any other ruleset on the host intact.")
	line("table inet vpn_hub")
	line("delete table inet vpn_hub")
	line("")
	line("table inet vpn_hub {")
	// The fingerprint travels with the ruleset itself rather than in a file beside
	// it, so reading it back cannot disagree with what is actually loaded: if
	// something flushes the table, the fingerprint goes with it.
	line("\tcomment %q", "vpn-hub:"+Fingerprint(plan))
	line("")

	for _, group := range plan.Egresses {
		line("\tset %s {", setName(group))
		line("\t\ttype ipv4_addr")
		line("\t\telements = { %s }", strings.Join(group.Addresses, ", "))
		line("\t}")
		line("")
	}

	for _, network := range plan.Internals {
		line("\tset %s {", internalSetName(network.TunnelID))
		line("\t\ttype ipv4_addr")
		// interval so subnets fit, and so dnsmasq can add single addresses it
		// resolves for this network's zones.
		line("\t\tflags interval")
		if len(network.Routes) > 0 {
			line("\t\telements = { %s }", strings.Join(network.Routes, ", "))
		}
		line("\t}")
		line("")
	}

	// Marking happens before routing so policy routing can act on the result. Internal
	// destinations are matched first: they outrank the profile's default egress.
	line("\tchain prerouting {")
	line("\t\ttype filter hook prerouting priority mangle; policy accept;")
	line("\t\tiifname != %q accept", plan.IngressInterface)
	for _, network := range plan.Internals {
		// `return` ends the chain here so the default-egress rule below cannot
		// overwrite the mark. Without it a private destination would be marked and
		// then immediately re-marked for the internet path, since setting a mark does
		// not stop evaluation.
		line("\t\tip daddr @%s meta mark set 0x%08x ct mark set meta mark return",
			internalSetName(network.TunnelID), network.Mark)
	}
	for _, group := range plan.Egresses {
		line("\t\tip saddr @%s meta mark set 0x%08x", setName(group), group.Mark)
	}
	line("\t\tct mark set meta mark")
	line("\t}")
	line("")

	// The kill switch is this chain's policy: traffic passes only on an explicit match
	// with an egress rule, so a tunnel that is down drops rather than falls back.
	line("\tchain forward {")
	line("\t\ttype filter hook forward priority filter; policy drop;")
	line("\t\tct state established,related accept")
	line("\t\tiifname %q oifname %q drop", plan.IngressInterface, plan.IngressInterface)
	for _, network := range plan.Internals {
		line("\t\tiifname %q ip daddr @%s oifname %q accept",
			plan.IngressInterface, internalSetName(network.TunnelID), network.Interface)
	}
	for _, group := range plan.Egresses {
		line("\t\tiifname %q ip saddr @%s oifname %q accept", plan.IngressInterface, setName(group), group.Interface)
	}
	// A proxy runs inside its namespace, so the connections it makes to its provider
	// are forwarded through here. A kernel tunnel keeps its socket in this namespace
	// and never appears in this chain at all.
	for _, group := range plan.Egresses {
		if group.Proxied {
			line("\t\tiifname %q oifname %q accept", group.Interface, plan.UplinkInterface)
		}
	}
	// A client aiming at a SOCKS endpoint is forwarded into that tunnel's namespace,
	// so the hole is bounded by the link it goes out of and by the client subnet:
	// nothing else on the host may reach a proxy that bypasses its own egress choice.
	for _, endpoint := range plan.Socks {
		line("\t\tiifname %q ip saddr %s oifname %q tcp dport %d accept",
			plan.IngressInterface, plan.ClientCIDR, endpoint.Interface, endpoint.Port)
	}
	line("\t}")
	line("")

	line("\tchain input {")
	line("\t\ttype filter hook input priority filter; policy drop;")
	line("\t\tct state established,related accept")
	line("\t\tiif lo accept")
	line("\t\tip protocol icmp accept")
	line("\t\ttcp dport %d accept", plan.ManagementPort)
	line("\t\tudp dport %d accept", plan.ListenPort)
	line("\t\tiifname %q ip daddr %s udp dport 53 accept", plan.IngressInterface, plan.DNSAddress)
	line("\t\tiifname %q ip daddr %s tcp dport 53 accept", plan.IngressInterface, plan.DNSAddress)
	line("\t}")
	line("")

	// Traffic the hub originates itself -- the resolver querying a private zone's
	// nameserver -- never passes through prerouting, so it needs marking here. The
	// chain is `type route` because only that makes the kernel reconsider the route
	// after the mark is set; a filter chain would mark the packet too late to matter.
	if len(plan.Internals) > 0 {
		line("\tchain output_mark {")
		line("\t\ttype route hook output priority mangle; policy accept;")
		for _, network := range plan.Internals {
			line("\t\tip daddr @%s meta mark set 0x%08x", internalSetName(network.TunnelID), network.Mark)
		}
		line("\t}")
		line("")
	}

	// The host itself must not emit IPv6: there is no IPv6 egress path, so anything
	// leaving this way would bypass every tunnel.
	line("\tchain output {")
	line("\t\ttype filter hook output priority filter; policy accept;")
	line("\t\tmeta nfproto ipv6 drop")
	line("\t}")
	line("")

	// Only traffic leaving through the host's own uplink is translated here. A tunnel
	// namespace does its own translation, to the address its provider issued, and
	// translating twice would hide the client address from the rule that does it --
	// the packet would arrive there sourced from this end of the veth instead.
	// Clients are pointed at the hub resolver, and any that ask elsewhere are brought
	// back to it. DNS-over-TLS is refused outright: it would carry private names past
	// split-DNS silently, and silence is the problem.
	line("\tchain prerouting_nat {")
	line("\t\ttype nat hook prerouting priority dstnat; policy accept;")
	// `dnat ip` rather than plain `dnat`: an inet table serves both families and
	// will not guess which one a rule means.
	line("\t\tiifname %q udp dport 53 dnat ip to %s:53", plan.IngressInterface, plan.DNSAddress)
	line("\t\tiifname %q tcp dport 53 dnat ip to %s:53", plan.IngressInterface, plan.DNSAddress)
	line("\t}")
	line("")

	line("\tchain postrouting {")
	line("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	for _, group := range plan.Egresses {
		if group.Interface == plan.UplinkInterface {
			line("\t\tip saddr %s oifname %q masquerade", plan.ClientCIDR, group.Interface)
		}
	}
	// Traffic the hub originates towards a tunnel -- the resolver querying a private
	// zone's nameserver -- carries the uplink address, and the namespace has no route
	// back to it. Translating it to this end of the veth gives the reply a way home.
	// Client traffic is excluded: it keeps its address so the tunnel sees who it is
	// serving, and the namespace translates it once on the way out.
	for _, network := range plan.Internals {
		line("\t\tip saddr != %s oifname %q masquerade", plan.ClientCIDR, network.Interface)
	}
	// A proxy's own connections leave from its side of the veth, an address the
	// internet cannot answer.
	if plan.LinkBase != "" && anyProxied(plan.Egresses) {
		line("\t\tip saddr %s oifname %q masquerade", plan.LinkBase, plan.UplinkInterface)
	}
	line("\t}")
	line("}")

	return out.String()
}

func anyProxied(groups []domain.EgressGroup) bool {
	for _, group := range groups {
		if group.Proxied {
			return true
		}
	}
	return false
}

// setName derives the nftables set holding one egress group's client addresses.
// Identifier safety comes from validation, which restricts tunnel IDs to a charset
// nftables accepts.
func setName(group domain.EgressGroup) string {
	if group.ID == domain.EgressDirect {
		return "client_direct"
	}
	return "client_" + strings.ReplaceAll(group.ID, "-", "_")
}

// NFTables applies a rendered ruleset through the nft binary. Feeding the whole
// ruleset to `nft -f -` gets a single transaction and error messages that carry a
// line number, neither of which the netlink bindings provide.
type NFTables struct {
	Binary string
	// Run defaults to executing commands for real.
	Run runner
	// RuntimeDir is where the ruleset is written before being loaded. Writing it
	// out rather than piping it in costs nothing -- the ruleset holds no secrets,
	// `nft list ruleset` shows the same thing -- and it means the file nft rejected
	// is still there to look at, with the line number nft named.
	RuntimeDir string
}

func (n NFTables) runtimeDir() string {
	if n.RuntimeDir != "" {
		return n.RuntimeDir
	}
	return "/run/vpn-hub"
}

func (n NFTables) binary() string {
	if n.Binary != "" {
		return n.Binary
	}
	return "nft"
}

// Observe reports the fingerprint carried by the live table, or an empty string when
// the table is absent — which is what drift usually looks like.
func (n NFTables) Observe(ctx context.Context) (string, error) {
	run := n.Run
	if run == nil {
		run = execRunner
	}
	output, err := run(ctx, n.binary(), "-j", "list", "table", "inet", "vpn_hub")
	if err != nil {
		// A missing table is the expected state before the first apply, and after
		// someone flushes the ruleset. Neither is an error.
		return "", nil //nolint:nilerr
	}
	return parseFingerprint(output)
}

// nftJSON is the slice of `nft -j list table` output that matters here.
type nftJSON struct {
	Nftables []struct {
		Table *struct {
			Comment string `json:"comment"`
		} `json:"table"`
	} `json:"nftables"`
}

func parseFingerprint(output string) (string, error) {
	var decoded nftJSON
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		return "", fmt.Errorf("decode nft output: %w", err)
	}
	for _, entry := range decoded.Nftables {
		if entry.Table != nil {
			return strings.TrimPrefix(entry.Table.Comment, "vpn-hub:"), nil
		}
	}
	return "", nil
}

// Fingerprint satisfies the port; the work is a pure function so it can be reused
// without an adapter.
func (n NFTables) Fingerprint(plan domain.FirewallPlan) string { return Fingerprint(plan) }

// Apply loads the ruleset, and reports whether it actually replaced the live one.
//
// It replaces the table only when the fingerprints differ, which is a deliberate
// narrowing of what this corrects. Replacement is atomic because it deletes the
// table and builds it again -- and that also empties the `internal_*` sets, which
// are not entirely derived from the plan: dnsmasq adds every address it resolves
// for a private zone as the answer goes past. Rebuilding on a timer therefore threw
// those addresses away every minute, and a packet to a private host whose address
// had just been forgotten did not fail -- it matched the default egress rule
// instead and left through the internet provider. Silent misrouting of exactly the
// traffic that must not take that path.
//
// The cost is that a rule edited in place, leaving the table comment intact, is no
// longer overwritten on the next tick. That is a deliberate act by someone who is
// already root on the hub, whereas the addresses were being lost continuously and
// by design.
func (n NFTables) Apply(ctx context.Context, plan domain.FirewallPlan) (bool, error) {
	loaded, err := n.Observe(ctx)
	if err == nil && loaded == Fingerprint(plan) {
		return false, nil
	}

	path := filepath.Join(n.runtimeDir(), "ruleset.nft")
	if _, err := writeIfChanged(path, RenderRuleset(plan), 0o600); err != nil {
		return false, fmt.Errorf("write nftables ruleset: %w", err)
	}

	run := n.Run
	if run == nil {
		run = execRunner
	}
	if _, err := run(ctx, n.binary(), "-f", path); err != nil {
		return false, fmt.Errorf("apply nftables ruleset: %w", err)
	}
	return true, nil
}
