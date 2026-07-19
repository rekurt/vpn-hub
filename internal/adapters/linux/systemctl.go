package linux

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// UnitStatus is the part of `systemctl show` worth relaying to an operator.
type UnitStatus struct {
	Unit string
	// Active is systemd's ActiveState: active, inactive, failed, activating.
	Active string
	// Sub refines it: running, dead, exited.
	Sub string
	// Since is when the main process started, as systemd formats it; empty when the
	// unit is not running.
	Since string
	// Restarts counts automatic restarts, which is how a crash-looping service looks
	// "active" at every glance while being in trouble.
	Restarts int
}

// Systemctl inspects and nudges systemd units. It exists for observability -- the
// units it touches are created elsewhere: the installed ones by deploy, the
// transient per-tunnel ones by the egress adapter.
type Systemctl struct {
	Run runner
}

func (s Systemctl) run(ctx context.Context, name string, args ...string) (string, error) {
	if s.Run != nil {
		return s.Run(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

// unitNamePattern is what a real systemd unit name looks like: it starts with an
// alphanumeric, so it can never be read as a command-line option.
var unitNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._-]*\.(service|timer|socket|target|mount)$`)

// ValidateUnitName rejects anything that is not a plausible unit name. Unit names
// reach these adapters from bot callback data, and while exec.Command runs no shell
// (so there is no injection), a name beginning with "-" could still be parsed as a
// flag; this closes that off before it can matter.
func ValidateUnitName(unit string) error {
	if !unitNamePattern.MatchString(unit) {
		return fmt.Errorf("refusing suspicious unit name %q", unit)
	}
	return nil
}

// Status describes one unit. Asking about a unit that does not exist is not an
// error: systemd answers with an inactive/dead status, and that answer is the truth.
func (s Systemctl) Status(ctx context.Context, unit string) (UnitStatus, error) {
	if err := ValidateUnitName(unit); err != nil {
		return UnitStatus{}, err
	}
	// The unit goes after `--` so it is always a positional argument, never an
	// option, whatever it starts with.
	output, err := s.run(ctx, "systemctl", "show",
		"--property=ActiveState,SubState,ExecMainStartTimestamp,NRestarts", "--", unit)
	if err != nil {
		return UnitStatus{}, err
	}
	status := UnitStatus{Unit: unit}
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "ActiveState":
			status.Active = value
		case "SubState":
			status.Sub = value
		case "ExecMainStartTimestamp":
			status.Since = value
		case "NRestarts":
			status.Restarts, _ = strconv.Atoi(value)
		}
	}
	if status.Active == "" {
		return UnitStatus{}, fmt.Errorf("systemctl show %s returned no ActiveState", unit)
	}
	return status, nil
}

// ListMatching names the units matching a glob, running or not. The transient
// per-tunnel services (vpn-hub-proxy-*, vpn-hub-openvpn-*, vpn-hub-socks-*) only
// exist while their tunnel does, so the answer is the current truth, not the config.
func (s Systemctl) ListMatching(ctx context.Context, pattern string) ([]UnitStatus, error) {
	output, err := s.run(ctx, "systemctl", "list-units", "--type=service", "--all",
		"--plain", "--no-legend", "--no-pager", pattern)
	if err != nil {
		return nil, err
	}
	var units []UnitStatus
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		units = append(units, UnitStatus{Unit: fields[0], Active: fields[2], Sub: fields[3]})
	}
	return units, nil
}

// Restart restarts one unit.
func (s Systemctl) Restart(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	_, err := s.run(ctx, "systemctl", "restart", "--", unit)
	return err
}
