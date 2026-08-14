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

// forwardedMSSClamp is the largest TCP MSS a forwarded connection may negotiate. It
// leaves room under a 1280-byte inner packet -- the smallest IPv6-era path worth
// planning for -- for the WireGuard and AmneziaWG obfuscation overhead the datagram
// then carries across the client's own uplink. Fixed rather than derived from a route
// MTU: the constraining hop is on the client side, which the hub never measures.
const forwardedMSSClamp = 1240

// internalSetName names the address set of one private network. Identifier safety
// comes from validation, which restricts tunnel IDs to a charset nftables accepts.
func internalSetName(tunnelID string) string {
	return "internal_" + strings.ReplaceAll(tunnelID, "-", "_")
}

// allowedSetName names the set of client addresses permitted to use one tunnel.
func allowedSetName(tunnelID string) string {
	return "allowed_" + strings.ReplaceAll(tunnelID, "-", "_")
}

// allowedSets collects the tunnels that need such a set, in a stable order.
//
// A tunnel can appear as an egress group, as a private network, or as a SOCKS
// endpoint -- often as more than one -- and they all answer to the same list, so the
// set is rendered once per tunnel rather than once per role.
func allowedSets(plan domain.FirewallPlan) []struct {
	id      string
	clients []string
} {
	type entry = struct {
		id      string
		clients []string
	}
	var result []entry
	seen := map[string]bool{}
	add := func(id string, clients []string) {
		if id == "" || id == domain.EgressDirect || seen[id] {
			return
		}
		seen[id] = true
		result = append(result, entry{id: id, clients: clients})
	}
	for _, group := range plan.Egresses {
		add(group.ID, group.Clients)
	}
	for _, network := range plan.Internals {
		add(network.TunnelID, network.Clients)
	}
	for _, endpoint := range plan.Socks {
		add(endpoint.TunnelID, endpoint.Clients)
	}
	return result
}

// rulesetFormatVersion is folded into the fingerprint so that a change to how a plan
// renders -- not just to the plan itself -- makes the agent re-apply the ruleset.
// The fingerprint is computed from the plan rather than the rendered text (the text
// carries the marker, so hashing it would have to hash around itself), which means a
// renderer fix alone leaves the fingerprint unchanged and never deploys. Bump this
// whenever RenderRuleset's output changes for an unchanged plan.
//
//	1: forwarded TCP MSS clamp matched on the SYN|RST mask, not a bare `flags syn`.
//	2: TCP/443 is accepted only when the REALITY fallback is on, and the UDP/443
//	   redirect moved into this table, scoped to the uplink.
const rulesetFormatVersion = 2

// Fingerprint identifies a firewall plan by its content and rendering format.
func Fingerprint(plan domain.FirewallPlan) string {
	payload, err := json.Marshal(struct {
		Version int                 `json:"version"`
		Plan    domain.FirewallPlan `json:"plan"`
	}{rulesetFormatVersion, plan})
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
		// Omitted when empty: `elements = { }` is a syntax error, and an egress
		// tunnel no device has chosen as its default has exactly that -- an empty
		// set. It still needs to exist, since rules refer to it.
		if len(group.Addresses) > 0 {
			line("\t\telements = { %s }", strings.Join(group.Addresses, ", "))
		}
		line("\t}")
		line("")
	}

	for _, tunnel := range allowedSets(plan) {
		line("\tset %s {", allowedSetName(tunnel.id))
		line("\t\ttype ipv4_addr")
		if len(tunnel.clients) > 0 {
			line("\t\telements = { %s }", strings.Join(tunnel.clients, ", "))
		}
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
	// Clamp the MSS of every forwarded TCP connection before anything else. A client
	// reaches the hub across a path whose MTU the hub cannot see -- a mobile carrier,
	// or a link that shrinks packets to disguise the tunnel -- and the encrypted
	// datagram carrying a full-size segment is silently dropped there. The handshake,
	// being small, still gets through, so the tunnel looks up while bulk transfer
	// stalls: pages never load though ping and DNS work. Clamping to a value that
	// survives the WireGuard and obfuscation overhead on top of the smallest path we
	// expect fixes it without depending on PMTU discovery, which such paths also break.
	// The rule sets an option and returns no verdict, so traversal continues to the
	// egress rules below. It precedes the established-state accept so the SYN and
	// SYN-ACK, which are new, are both reached.
	//
	// Match on `flags & (syn|rst) == syn`, not a bare `flags syn`: the bare form
	// compiles to an equality test on the whole flags byte and so matches only a pure
	// SYN (0x02), missing the SYN-ACK (0x12). The MSS in the SYN bounds one direction
	// and the MSS in the SYN-ACK the other, so clamping only the SYN would leave the
	// server->client segment size unclamped and half the transfers still stalling.
	line("\t\ttcp flags & (syn|rst) == syn tcp option maxseg size set %d", forwardedMSSClamp)
	line("\t\tct state established,related accept")
	line("\t\tiifname %q oifname %q drop", plan.IngressInterface, plan.IngressInterface)
	// DNS-over-TLS is refused before any egress rule can accept it. A client that
	// resolves a private name through a public resolver gets an answer the hub never
	// saw, so the address never enters the private network's set and the packet that
	// follows leaves through the internet provider instead. Reset rather than drop:
	// a client whose DoT connection is refused falls back to plain DNS at once,
	// where split-DNS can answer it, instead of waiting out a timeout first.
	//
	// DNS-over-HTTPS is not blocked and cannot usefully be: it is indistinguishable
	// from the rest of port 443. Split-DNS therefore depends on clients not having
	// DoH forced on, which is a real limit and not a solved problem.
	line("\t\tiifname %q tcp dport 853 reject with tcp reset", plan.IngressInterface)
	for _, network := range plan.Internals {
		line("\t\tiifname %q ip saddr @%s ip daddr @%s oifname %q accept",
			plan.IngressInterface, allowedSetName(network.TunnelID),
			internalSetName(network.TunnelID), network.Interface)
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
	// The same is true of a private network carried by sing-box or OpenVPN. Without
	// this the process inside the namespace cannot reach its provider at all, so the
	// tunnel never comes up -- and nothing says why.
	for _, network := range plan.Internals {
		if network.Proxied {
			line("\t\tiifname %q oifname %q accept", network.Interface, plan.UplinkInterface)
		}
	}
	// A client aiming at a SOCKS endpoint is forwarded into that tunnel's namespace,
	// so the hole is bounded by the link it goes out of and by the client subnet:
	// nothing else on the host may reach a proxy that bypasses its own egress choice.
	for _, endpoint := range plan.Socks {
		line("\t\tiifname %q ip saddr @%s oifname %q tcp dport %d accept",
			plan.IngressInterface, allowedSetName(endpoint.TunnelID), endpoint.Interface, endpoint.Port)
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
	// REALITY is a TCP fallback for networks that discard encrypted UDP. Kept in
	// the reconciled table rather than a parallel one: verdicts from a second base
	// chain do not bypass this chain's drop policy. Conditional, because a port
	// accepted with nothing listening behind it is attack surface offered for free.
	if plan.RealityPort != 0 {
		line("\t\ttcp dport %d accept", plan.RealityPort)
	}
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
		// A socket that already chose its way out keeps it. This marks by destination
		// alone -- it cannot see who asked -- so without this guard it would also
		// re-mark the fallback listener's connections, which carry the mark of the
		// egress their device was assigned. A device excluded from a private network
		// by allowed_devices would then reach it anyway, because that list is enforced
		// in the forward chain and this traffic never passes through it. Refusing
		// private destinations in the listener's own configuration is not enough on
		// its own: a private network may legitimately route a public prefix, and split
		// DNS adds whatever addresses its zones resolve to.
		line("\t\tmeta mark != 0x00000000 return")
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
	// The kill switch for traffic the hub originates on a client's behalf.
	//
	// Marked traffic is steered by `ip rule fwmark N lookup N`, and that construct
	// fails OPEN: a table with no matching route is a lookup that falls through to
	// the next rule and then to main, so the packet leaves by the hub's own uplink
	// carrying the hub's address. Forwarded client traffic is safe from this because
	// the forward chain's drop policy only accepts it out of the interface its mark
	// belongs to -- but the REALITY listener's connections, and the resolver's
	// queries into a private zone, never pass through forward at all.
	//
	// So the same guarantee is stated here explicitly: a marked packet leaving by
	// anything other than its own interface is dropped rather than delivered by the
	// wrong path.
	for _, group := range plan.Egresses {
		if group.ID == domain.EgressDirect {
			continue // direct means the uplink, which is where unmarked traffic goes
		}
		line("\t\tmeta mark 0x%08x oifname != %q drop", group.Mark, group.Interface)
	}
	for _, network := range plan.Internals {
		line("\t\tmeta mark 0x%08x oifname != %q drop", network.Mark, network.Interface)
	}
	line("\t}")
	line("")

	// Only traffic leaving through the host's own uplink is translated here. A tunnel
	// namespace does its own translation, to the address its provider issued, and
	// translating twice would hide the client address from the rule that does it --
	// the packet would arrive there sourced from this end of the veth instead.
	// Clients are pointed at the hub resolver, and any that ask elsewhere are brought
	// back to it; DNS-over-TLS is refused in the forward chain above.
	line("\tchain prerouting_nat {")
	line("\t\ttype nat hook prerouting priority dstnat; policy accept;")
	// `dnat ip` rather than plain `dnat`: an inet table serves both families and
	// will not guess which one a rule means.
	line("\t\tiifname %q udp dport 53 dnat ip to %s:53", plan.IngressInterface, plan.DNSAddress)
	line("\t\tiifname %q tcp dport 53 dnat ip to %s:53", plan.IngressInterface, plan.DNSAddress)
	// The UDP fallback, for networks that block UDP/51820 by port rather than
	// discarding UDP as such. Scoped to the uplink: an unscoped rule also matches
	// client traffic arriving on the ingress interface, so a forwarded QUIC or
	// HTTP/3 request to any site's :443 would have its destination port rewritten to
	// the ingress and silently break. Conntrack reverses it for the replies, as it
	// already does for the DNS rules above.
	//
	// `dnat to :port` rather than `redirect`, which would also rewrite the
	// destination address to the incoming interface's primary one: where clients
	// dial a secondary or floating address, the reply would then be sourced from the
	// primary and the client would discard it as coming from the wrong endpoint.
	if plan.AltUDP443 {
		line("\t\tiifname %q meta nfproto ipv4 udp dport %d dnat to :%d",
			plan.UplinkInterface, domain.RealityPort, plan.ListenPort)
	}
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
	if plan.LinkBase != "" && anyProxied(plan) {
		line("\t\tip saddr %s oifname %q masquerade", plan.LinkBase, plan.UplinkInterface)
	}
	line("\t}")
	line("}")

	return out.String()
}

func anyProxied(plan domain.FirewallPlan) bool {
	for _, group := range plan.Egresses {
		if group.Proxied {
			return true
		}
	}
	for _, network := range plan.Internals {
		if network.Proxied {
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
	return DefaultRuntimeDir
}

func (n NFTables) binary() string {
	if n.Binary != "" {
		return n.Binary
	}
	return "nft"
}

// Observe reports the fingerprint carried by the live table, or an empty string when
// the table is absent -- which is what drift usually looks like.
//
// Absence and ignorance are told apart. nft exits 1 with "No such file or directory"
// for a table that is not there, which is the expected state before the first apply
// and after someone flushes the ruleset. Anything else -- nft missing, permission
// denied, unreadable output -- used to produce the same answer, so a hub that could
// not look at its own ruleset reported that the ruleset had been flushed, and the
// agent set about rebuilding a table that may have been perfectly correct.
func (n NFTables) Observe(ctx context.Context) (string, error) {
	run := n.Run
	if run == nil {
		run = execRunner
	}
	output, err := run(ctx, n.binary(), "-j", "list", "table", "inet", "vpn_hub")
	if err != nil {
		if isMissingTable(err) {
			return "", nil
		}
		return "", fmt.Errorf("read the loaded ruleset: %w", err)
	}
	return parseFingerprint(output)
}

// isMissingTable recognises nft's way of saying the table does not exist.
func isMissingTable(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such file or directory") ||
		strings.Contains(message, "does not exist")
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
