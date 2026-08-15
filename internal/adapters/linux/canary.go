package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/domain"
)

// canaryNamespace is where a candidate is tried. One at a time, so the name is fixed.
const canaryNamespace = "vpn-hub-canary"

// Canary tries a candidate upstream in a namespace of its own before anything is
// allowed to depend on it.
//
// A subscription changes at the provider without warning, so applying whatever
// arrives and finding out afterwards is the worst available order: the tunnel it
// replaces is the one carrying traffic. A candidate is proven first, and the active
// configuration is only replaced by one that worked.
type Canary struct {
	Egress Egress
	Run    runner
	// Probe is the URL fetched through the candidate. Reaching it is the whole
	// evidence that the candidate works.
	Probe   string
	Timeout time.Duration
}

func (c Canary) run(ctx context.Context, name string, args ...string) (string, error) {
	return c.Run.or()(ctx, name, args...)
}

func (c Canary) probe() string {
	if c.Probe != "" {
		return c.Probe
	}
	return "https://1.1.1.1/cdn-cgi/trace"
}

func (c Canary) timeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	return 20 * time.Second
}

// lock serializes canary runs across processes. The namespace, veth and unit names
// are fixed, so a bot-driven refresh and a hubctl one racing each other tear down
// each other's half-built candidate; the flock makes the second wait instead.
func (c Canary) lock() (func(), error) {
	dir := c.Egress.secretsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	return runtimeadapter.LockDir(dir)
}

// Try brings a candidate up in an isolated namespace, fetches through it and tears
// the namespace down again. It reports nil only when traffic actually passed.
func (c Canary) Try(ctx context.Context, candidate domain.ProxyTunnel, uplink string) error {
	release, err := c.lock()
	if err != nil {
		return err
	}
	defer release()
	return c.try(ctx, candidate, uplink)
}

func (c Canary) try(ctx context.Context, candidate domain.ProxyTunnel, uplink string) error {
	spec := domain.EgressSpec{
		TunnelID:  "canary",
		Namespace: canaryNamespace,
		HostVeth:  "vh-canary",
		PeerVeth:  peerVethName,
		// A link range of its own, outside the one the reconciler hands out, so a
		// candidate under test can never collide with a tunnel in service.
		HostAddress: "10.91.0.1/30",
		PeerAddress: "10.91.0.2/30",
		ClientCIDR:  "10.91.0.0/30",
		Interface:   SingBoxTunInterface,
		Type:        domain.TunnelXray,
		Proxy:       candidate,
	}

	defer func() {
		// The firewall hole goes first, and on a deadline of its own.
		//
		// It is the one piece of this teardown that nothing else ever cleans up: a
		// leaked vpn_hub_canary table keeps an accept and a masquerade hooked into
		// forward/postrouting, and the agent only replaces its own inet vpn_hub
		// table. Sharing one budget with the steps above it meant a namespace
		// deletion that hung could eat the whole timeout and leave the hole open
		// with the context already cancelled.
		discard, cancelDiscard := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancelDiscard()
		c.Discard(discard)

		// Then the rest: a candidate that failed must not leave a namespace behind
		// for the next attempt to trip over.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _ = c.run(cleanup, "systemctl", "stop", "vpn-hub-proxy-canary.service")
		_ = c.Egress.namespaceLifecycle(cleanup, "del", canaryNamespace)
		_, _ = c.run(cleanup, "ip", "link", "del", spec.HostVeth)
	}()

	if err := c.Egress.applyOne(ctx, spec); err != nil {
		return fmt.Errorf("bring the candidate up: %w", err)
	}
	if err := c.allowCanaryOut(ctx, spec, uplink); err != nil {
		return err
	}

	seconds := strconv.Itoa(int(c.timeout().Seconds()))
	if _, err := c.run(ctx, "ip", "netns", "exec", canaryNamespace,
		"curl", "-sS", "--max-time", seconds, "-o", "/dev/null", c.probe()); err != nil {
		return fmt.Errorf("the candidate did not carry traffic: %w", err)
	}
	return nil
}

// allowCanaryOut lets the candidate's own connections reach its provider. The hub's
// forward policy is drop, and the canary link is not in any revision, so it needs an
// explicit and equally temporary hole.
func (c Canary) allowCanaryOut(ctx context.Context, spec domain.EgressSpec, uplink string) error {
	ruleset := fmt.Sprintf(`table inet vpn_hub_canary
delete table inet vpn_hub_canary

table inet vpn_hub_canary {
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname %q oifname %q accept
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr %s oifname %q masquerade
	}
}
`, spec.HostVeth, uplink, spec.ClientCIDR, uplink)

	path := filepath.Join(c.Egress.secretsDir(), "canary.nft")
	if _, err := writeIfChanged(path, ruleset, 0o600); err != nil {
		return err
	}
	_, err := c.run(ctx, "nft", "-f", path)
	return err
}

// Discard removes the temporary ruleset. Every path through try runs it, so a
// caller never needs to; it stays exported for callers that want to sweep up
// after an interrupted run from a previous process.
func (c Canary) Discard(ctx context.Context) {
	_, _ = c.run(ctx, "nft", "delete", "table", "inet", "vpn_hub_canary")
	_ = os.Remove(filepath.Join(c.Egress.secretsDir(), "canary.nft"))
}

// peerVethName mirrors the application layer's choice so a canary namespace looks
// like any other from the inside.
const peerVethName = "uplink0"

// SelectCandidate tries candidates in order and returns the first that carries
// traffic, with the reasons the others were rejected. The lock is held across the
// whole selection, not per candidate: interleaving two selections would still
// thrash the shared namespace between them. progress, when non-nil, is called
// before each attempt with the 1-based index, the total and the rejections so far.
func (c Canary) SelectCandidate(ctx context.Context, candidates []domain.ProxyTunnel, uplink string,
	progress func(tried, total int, rejected []string)) (domain.ProxyTunnel, []string, error) {
	release, err := c.lock()
	if err != nil {
		return domain.ProxyTunnel{}, nil, err
	}
	defer release()

	var reasons []string
	for index, candidate := range candidates {
		if progress != nil {
			progress(index+1, len(candidates), reasons)
		}
		err := c.try(ctx, candidate, uplink)
		if err == nil {
			return candidate, reasons, nil
		}
		reasons = append(reasons, fmt.Sprintf("%s:%d: %v", candidate.Server, candidate.Port, err))
		if ctx.Err() != nil {
			break
		}
	}
	return domain.ProxyTunnel{}, reasons, fmt.Errorf("no candidate carried traffic:\n  %s",
		strings.Join(reasons, "\n  "))
}
