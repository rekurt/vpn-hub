package linux

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-hub/internal/domain"
)

// realityUnit is the transient unit the listener runs as. Transient rather than a
// shipped unit file because the configuration it reads holds a private key and a
// credential per device: it belongs in the runtime tmpfs, is rewritten whenever the
// device list changes, and is rebuilt from the revision after every reboot.
const realityUnit = "vpn-hub-reality"

// RealityConfigName is the rendered listener configuration inside the runtime dir.
const RealityConfigName = "reality-singbox.json"

// RealityIngress runs the TCP/443 fallback listener on the hub itself.
//
// Unlike an egress it lives in the main namespace: it is a way *in*, and the
// connections it opens on a client's behalf are hub-originated traffic that the
// existing policy routing already knows how to steer.
type RealityIngress struct {
	Run        runner
	SecretsDir string
}

func (r RealityIngress) run(ctx context.Context, name string, args ...string) (string, error) {
	if r.Run != nil {
		return r.Run(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

func (r RealityIngress) secretsDir() string {
	if r.SecretsDir != "" {
		return r.SecretsDir
	}
	return DefaultRuntimeDir
}

// Apply brings the listener to what the spec asks for, including asking for it to
// be gone. A disabled spec is not a no-op: turning the fallback off in
// configuration has to close the port on the next reconcile.
func (r RealityIngress) Apply(ctx context.Context, spec domain.RealityIngressSpec) error {
	path := filepath.Join(r.secretsDir(), RealityConfigName)

	if !spec.Enabled {
		// Unconditional. `is-active` reports non-zero for a unit that is merely
		// `activating`, which is exactly where a crash-looping listener sits during
		// its RestartSec backoff -- asking first would skip the stop and leave it
		// looping after the operator switched the fallback off.
		if err := r.stopListener(ctx); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		if err := os.Remove(r.appliedPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", r.appliedPath(), err)
		}
		return nil
	}

	config, err := RenderRealityServerConfig(spec)
	if err != nil {
		return err
	}
	// 0600: the file holds the listener's private key and every device's credential.
	if _, err := writeIfChanged(path, config, 0o600); err != nil {
		return err
	}

	// Whether the rendered configuration is already *running* -- which is not the
	// same question as whether it is already written.
	//
	// The file has to be on disk before the unit can be started from it, so a pass
	// that writes it and then fails to replace the process leaves the new bytes
	// beside the old listener. Reading the file back would call that applied, skip
	// the work and report success, while the running process kept serving the user
	// list it started with: a revoked device would stay admitted until something
	// else happened to change the configuration again. The fingerprint below is
	// written only after a replacement that worked, so a failed one is retried on
	// the next pass instead of being remembered as done.
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(config)))
	if applied, err := r.Applied(ctx); err == nil && applied == fingerprint {
		return nil
	}

	// Asked before starting, because systemd-run cannot answer it. It returns once
	// the job is accepted, and a Type=simple process that dies a moment later --
	// over a configuration this release rejects -- still looks like a success. A
	// rejected configuration is deterministic, so it is worth catching here rather
	// than as a unit that restarts forever while every reconcile reports fine.
	if _, err := r.run(ctx, "sing-box", "check", "-c", path); err != nil {
		return fmt.Errorf("the rendered listener configuration was rejected: %w", err)
	}

	// Checked here as much as on the way out, and for a sharper reason. The user
	// list lives in the running process, so replacing it is how a revoked device
	// stops being admitted. A stop that quietly failed would leave systemd-run
	// unable to reuse the unit name, the old process still serving the old list,
	// and the reconcile reporting that it had applied the revision that removed
	// the device.
	if err := r.stopListener(ctx); err != nil {
		return err
	}
	if _, err := r.run(ctx, "systemd-run", "--quiet", "--collect", "--unit="+realityUnit,
		"--property=Restart=on-failure", "--property=RestartSec=5s",
		// Confined like the agent that starts it. CAP_NET_BIND_SERVICE for :443 and
		// CAP_NET_ADMIN for the socket marks that steer each device into its egress;
		// nothing here needs to write to the filesystem.
		"--property=NoNewPrivileges=true", "--property=UMask=0077",
		"--property=ProtectSystem=strict", "--property=ProtectHome=true",
		"--property=PrivateTmp=true",
		"--property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN",
		"--property=AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN",
		"sing-box", "run", "-c", path); err != nil {
		return err
	}
	if err := r.confirmRunning(ctx); err != nil {
		return err
	}
	// Recorded last, so it means "this is what is running" rather than "this is
	// what was rendered".
	if _, err := writeIfChanged(r.appliedPath(), fingerprint, 0o600); err != nil {
		return err
	}
	return nil
}

// appliedPath holds the fingerprint of the configuration the running listener
// was actually started from.
func (r RealityIngress) appliedPath() string {
	return filepath.Join(r.secretsDir(), RealityConfigName+".applied")
}

// Fingerprint is what Applied returns for a listener started from this spec.
//
// Taken over the rendered configuration rather than the spec, because that is
// what the process actually reads: two specs that render alike are the same
// listener, and a spec field that reaches the file -- the key included, which the
// spec deliberately keeps out of its own JSON -- changes it.
func (r RealityIngress) Fingerprint(spec domain.RealityIngressSpec) string {
	if !spec.Enabled {
		return ""
	}
	config, err := RenderRealityServerConfig(spec)
	if err != nil {
		// A spec that will not render is one no listener can be running from.
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(config)))
}

// Applied reports what the running listener was started from.
//
// Empty when nothing is running, and deliberately so: a listener someone stopped
// is a difference from the revision, not the absence of one. Without this the
// fallback was invisible to Observe and Diff, so a dry run reported a clean host
// while a real pass would restart it, and the drift watcher never mentioned a
// listener that had been stopped.
func (r RealityIngress) Applied(ctx context.Context) (string, error) {
	if _, err := r.run(ctx, "systemctl", "is-active", "--quiet", realityUnit+".service"); err != nil {
		return "", nil
	}
	fingerprint, err := os.ReadFile(r.appliedPath())
	if err != nil {
		if os.IsNotExist(err) {
			// Running, but from a configuration this hub did not record applying:
			// started by hand, or left over from a pass that died between the two.
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", r.appliedPath(), err)
	}
	return strings.TrimSpace(string(fingerprint)), nil
}

// stopListener stops the unit and reports a stop that did not work.
//
// Only "there is no such unit" is not a failure -- systemd answers that with exit
// 5 and says so, and it is the ordinary state of a hub that never turned the
// fallback on. Anything else (a timeout, a lost connection to systemd, a
// cancelled context) means the listener may still be accepting on 443, and
// removing its configuration and reporting success would leave the operator
// believing a port is shut while it is open. Every reconcile would repeat the
// belief.
func (r RealityIngress) stopListener(ctx context.Context) error {
	_, err := r.run(ctx, "systemctl", "stop", realityUnit+".service")
	if err == nil || strings.Contains(err.Error(), "not loaded") {
		return nil
	}
	return fmt.Errorf("stop the listener: %w", err)
}

// confirmRunning reports a listener that died on startup.
//
// Everything systemd-run's success means is that the job was accepted. A port
// already in use, a missing binary, a kernel that refuses the capabilities: all
// of them leave a unit that fails immediately afterwards, and with Restart
// on-failure it then fails on a timer. Nothing else would notice -- the fallback
// is not part of Observe, so no drift is reported -- and every reconcile would
// claim success while the way in stayed shut.
func (r RealityIngress) confirmRunning(ctx context.Context) error {
	// SubState, and neither `is-active` nor ActiveState.
	//
	// `is-active` answers a failed unit with the word on stdout and exit 3, and a
	// non-zero exit is where execRunner drops stdout and returns the error instead:
	// asking that way reads as an empty string, matches no state, and reports
	// nothing. ActiveState is no better here, because a unit that starts, dies and
	// is waiting out RestartSec reports `activating` -- the same word as one that
	// is genuinely still starting. SubState separates them: `auto-restart` is a
	// listener that ran and did not survive, `running` is one that did.
	//
	// Watched for a moment rather than asked once. A process that cannot bind its
	// port is `running` for the instant between exec and its first syscall, so
	// returning on the first `running` reports success on exactly the failure this
	// is here to catch. The window is short because the question is whether it
	// survived starting, not whether it is still up minutes later -- that is the
	// next reconcile's business -- and it is only paid when the listener was
	// actually (re)started, not on the passes that find it already up.
	for attempt := range 8 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		state, err := r.run(ctx, "systemctl", "show", realityUnit+".service",
			"--property=SubState", "--value")
		if err != nil {
			return fmt.Errorf("ask systemd about the listener: %w", err)
		}
		switch strings.TrimSpace(state) {
		case "auto-restart", "failed", "dead":
			// dead as well as failed: --collect garbage-collects a unit that stops,
			// so one that died a moment ago may already read as dead.
			journal, _ := r.run(ctx, "journalctl", "-u", realityUnit, "--no-pager", "-n", "10")
			return fmt.Errorf("the listener did not stay up:\n%s", strings.TrimSpace(journal))
		}
	}
	// It has been running for two seconds without falling over. Anything later is
	// the next pass's to notice.
	return nil
}

// RenderRealityServerConfig builds the listener's configuration.
//
// Pure, so the policy can be reviewed and diffed without a host -- the same reason
// the nftables renderer is pure.
//
// Per-device egress is the interesting part. Each device authenticates as itself,
// and a route rule sends its connections to an outbound carrying its egress
// tunnel's fwmark. The kernel's policy routing -- the same `ip rule fwmark N table
// N` the reconciler already installs, and the same path the hub's own resolver
// takes into a private network -- does the rest. Private zones still outrank it:
// the output_mark chain re-marks those destinations before the routing decision, so
// a device reaches corporate resources through their tunnel whichever egress it
// chose.
func RenderRealityServerConfig(spec domain.RealityIngressSpec) (string, error) {
	if spec.ServerName == "" {
		return "", fmt.Errorf("the REALITY listener needs a server_name to mimic")
	}
	if spec.PrivateKey == "" || spec.ShortID == "" {
		return "", fmt.Errorf("the REALITY listener needs a private key and a short id")
	}
	if spec.Port == 0 {
		return "", fmt.Errorf("the REALITY listener needs a port")
	}

	users := make([]any, 0, len(spec.Users))
	rules := make([]any, 0, len(spec.Users))
	// One outbound per distinct mark rather than per device: two devices sharing an
	// egress share the route out of the hub, and duplicate outbounds would only make
	// the rendered file longer and the diff noisier.
	marked := make(map[uint32]string)
	outbounds := []any{directOutbound("direct", 0), map[string]any{"type": "block", "tag": "block"}}

	for _, user := range spec.Users {
		if user.DeviceID == "" || user.UUID == "" {
			return "", fmt.Errorf("a REALITY user needs a device id and a credential")
		}
		users = append(users, map[string]any{
			"name": user.DeviceID,
			"uuid": user.UUID,
			// Vision is what current clients default to for REALITY, and the server
			// has to agree: a flow mismatch fails after a successful handshake, which
			// reads to the operator as "connects but no traffic".
			"flow": "xtls-rprx-vision",
		})
		if user.Mark == 0 {
			continue // the default outbound already leaves through the hub's uplink
		}
		tag, known := marked[user.Mark]
		if !known {
			tag = fmt.Sprintf("egress-%d", user.Mark)
			marked[user.Mark] = tag
			outbounds = append(outbounds, directOutbound(tag, user.Mark))
		}
		rules = append(rules, map[string]any{
			"auth_user": []string{user.DeviceID},
			"outbound":  tag,
		})
	}

	// Refused before anything else. This path does not pass through the forward
	// chain, so none of the packet filter's client rules apply to it: without this,
	// an authenticated device could reach the hub's own loopback services, the other
	// clients' addresses, the tunnel namespaces' SOCKS ports, and every private
	// network the hub can see -- including ones its allowed_devices deliberately
	// exclude it from. Private destinations belong to the AmneziaWG path, where the
	// packet filter can tell who is asking.
	rules = append([]any{map[string]any{"ip_is_private": true, "outbound": "block"}}, rules...)

	route := map[string]any{
		"rules": rules,
		"final": "direct",
		// One interface, one routing table: there is nothing here to detect.
		"auto_detect_interface": false,
	}

	config := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": false},
		// Names are resolved through the hub's own resolver, so this path gets the
		// same split DNS as every other: private zones answer from inside their
		// tunnels, and the answers land in the packet filter's sets on the way past.
		"dns": map[string]any{
			"servers":  []any{map[string]any{"tag": "hub", "address": spec.DNSAddress}},
			"strategy": "ipv4_only",
		},
		"inbounds": []any{map[string]any{
			"type": "vless",
			"tag":  "reality-in",
			// IPv4 only: the host has no IPv6 egress and its output chain drops it,
			// so a listener on both families would accept what it cannot answer.
			"listen":      "0.0.0.0",
			"listen_port": spec.Port,
			"users":       users,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": spec.ServerName,
				"reality": map[string]any{
					"enabled": true,
					// Where an unauthenticated connection is handed, which is what
					// makes the port look like an ordinary HTTPS site to anyone
					// scanning it.
					"handshake":   map[string]any{"server": spec.ServerName, "server_port": 443},
					"private_key": spec.PrivateKey,
					"short_id":    []string{spec.ShortID},
				},
			},
		}},
		"outbounds": outbounds,
		"route":     route,
	}

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode REALITY configuration: %w", err)
	}
	return string(encoded) + "\n", nil
}

func directOutbound(tag string, mark uint32) map[string]any {
	outbound := map[string]any{
		"type": "direct",
		"tag":  tag,
		// The host has no IPv6 path out, so resolving to one would black-hole the
		// connection.
		"domain_strategy": "ipv4_only",
	}
	if mark != 0 {
		outbound["routing_mark"] = mark
	}
	return outbound
}
