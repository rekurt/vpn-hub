package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"vpn-hub/internal/domain"
)

func TestAtomicWriteLeavesNoTemporaryFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := atomicWrite(path, []byte(`{"revision":"a"}`), 0o600); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("expected only state.json, found %s", strings.Join(names, ", "))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
	}
}

// Concurrent writers previously shared a fixed "<path>.tmp" name and could interleave
// into a truncated file. The reader must always observe a complete revision.
func TestConcurrentSavesNeverExposeAPartialFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := FileRevisionStore{StateDir: dir}

	var writers sync.WaitGroup
	for i := range 16 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			state := domain.DesiredState{Revision: strings.Repeat("abcd", i+1)}
			if err := store.Save(context.Background(), state); err != nil {
				t.Errorf("save: %v", err)
			}
		}()
	}
	writers.Wait()

	data, err := os.ReadFile(filepath.Join(dir, desiredStateFile))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state domain.DesiredState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("state file is not valid JSON after concurrent writes: %v", err)
	}
	if state.Revision == "" {
		t.Fatal("expected a revision to survive")
	}
}
