package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"vpn-hub/internal/domain"
)

const internalSet = "internal_v4"

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

	hasInternal := len(plan.InternalRoutes) > 0
	if hasInternal {
		line("\tset %s {", internalSet)
		line("\t\ttype ipv4_addr")
		line("\t\tflags interval")
		line("\t\telements = { %s }", strings.Join(plan.InternalRoutes, ", "))
		line("\t}")
		line("")
	}

	// Marking happens before routing so policy routing can act on the result. Internal
	// destinations are matched first: they outrank the profile's default egress.
	line("\tchain prerouting {")
	line("\t\ttype filter hook prerouting priority mangle; policy accept;")
	line("\t\tiifname != %q accept", plan.IngressInterface)
	if hasInternal {
		line("\t\tip daddr @%s accept", internalSet)
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
	if hasInternal {
		line("\t\tiifname %q ip daddr @%s accept", plan.IngressInterface, internalSet)
	}
	for _, group := range plan.Egresses {
		line("\t\tiifname %q ip saddr @%s oifname %q accept", plan.IngressInterface, setName(group), group.Interface)
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

	// The host itself must not emit IPv6: there is no IPv6 egress path, so anything
	// leaving this way would bypass every tunnel.
	line("\tchain output {")
	line("\t\ttype filter hook output priority filter; policy accept;")
	line("\t\tmeta nfproto ipv6 drop")
	line("\t}")
	line("")

	line("\tchain postrouting {")
	line("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	for _, group := range plan.Egresses {
		line("\t\tip saddr %s oifname %q masquerade", plan.ClientCIDR, group.Interface)
	}
	line("\t}")
	line("}")

	return out.String()
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

func (n NFTables) Apply(ctx context.Context, plan domain.FirewallPlan) error {
	command := exec.CommandContext(ctx, n.binary(), "-f", "-")
	command.Stdin = strings.NewReader(RenderRuleset(plan))

	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return fmt.Errorf("apply nftables ruleset: %w: %s", err, message)
		}
		return fmt.Errorf("apply nftables ruleset: %w", err)
	}
	return nil
}
