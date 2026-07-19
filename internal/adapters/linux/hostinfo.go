package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// HostSnapshot is the handful of numbers an operator glances at first when asking
// whether the machine itself, rather than a tunnel, is the problem.
type HostSnapshot struct {
	Uptime time.Duration
	// Load averages stay strings: they are relayed, not computed with.
	Load1, Load5, Load15 string
	DiskTotal, DiskFree  uint64
}

// HostInfo reads the host's vital signs from /proc and statfs. No shelling out:
// everything here has a stable kernel interface.
type HostInfo struct {
	// ProcDir defaults to /proc; tests point it at a directory of fixtures.
	ProcDir string
	// Mount is the filesystem to report disk usage for, / by default.
	Mount string
}

func (h HostInfo) procDir() string {
	if h.ProcDir != "" {
		return h.ProcDir
	}
	return "/proc"
}

func (h HostInfo) mount() string {
	if h.Mount != "" {
		return h.Mount
	}
	return "/"
}

func (h HostInfo) Snapshot() (HostSnapshot, error) {
	var snapshot HostSnapshot

	uptime, err := os.ReadFile(filepath.Join(h.procDir(), "uptime"))
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read uptime: %w", err)
	}
	fields := strings.Fields(string(uptime))
	if len(fields) == 0 {
		return HostSnapshot{}, fmt.Errorf("uptime is empty")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("parse uptime %q: %w", fields[0], err)
	}
	snapshot.Uptime = time.Duration(seconds * float64(time.Second)).Round(time.Second)

	loadavg, err := os.ReadFile(filepath.Join(h.procDir(), "loadavg"))
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read loadavg: %w", err)
	}
	loads := strings.Fields(string(loadavg))
	if len(loads) < 3 {
		return HostSnapshot{}, fmt.Errorf("loadavg has %d fields", len(loads))
	}
	snapshot.Load1, snapshot.Load5, snapshot.Load15 = loads[0], loads[1], loads[2]

	var stat syscall.Statfs_t
	if err := syscall.Statfs(h.mount(), &stat); err != nil {
		return HostSnapshot{}, fmt.Errorf("statfs %s: %w", h.mount(), err)
	}
	snapshot.DiskTotal = stat.Blocks * uint64(stat.Bsize)
	snapshot.DiskFree = stat.Bavail * uint64(stat.Bsize)
	return snapshot, nil
}
