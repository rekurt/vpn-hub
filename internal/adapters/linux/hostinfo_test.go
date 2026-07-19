package linux

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotReadsProc(t *testing.T) {
	t.Parallel()
	proc := t.TempDir()
	if err := os.WriteFile(filepath.Join(proc, "uptime"), []byte("93784.50 180000.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "loadavg"), []byte("0.15 0.10 0.05 1/123 4567\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	snapshot, err := HostInfo{ProcDir: proc, Mount: proc}.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if expected := 26*time.Hour + 3*time.Minute + 5*time.Second; snapshot.Uptime != expected {
		t.Fatalf("expected uptime %v, got %v", expected, snapshot.Uptime)
	}
	if snapshot.Load1 != "0.15" || snapshot.Load5 != "0.10" || snapshot.Load15 != "0.05" {
		t.Fatalf("unexpected load %q %q %q", snapshot.Load1, snapshot.Load5, snapshot.Load15)
	}
	if snapshot.DiskTotal == 0 || snapshot.DiskFree == 0 {
		t.Fatalf("statfs returned zeros: %+v", snapshot)
	}
}

func TestSnapshotFailsWithoutProc(t *testing.T) {
	t.Parallel()
	if _, err := (HostInfo{ProcDir: t.TempDir()}).Snapshot(); err == nil {
		t.Fatal("expected missing /proc files to be an error")
	}
}
