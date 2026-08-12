package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A profile carries the device's private key, and os.WriteFile applies its mode
// only when it creates the file -- so re-issuing over a target that already
// exists with permissive bits would leave the credential readable by every local
// user, silently and only on the second run.
func TestWriteProfileSecuresAnExistingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "macbook.conf")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeProfile(path, "[Interface]\nPrivateKey = secret\n"); err != nil {
		t.Fatalf("writeProfile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 0600 -- the private key is readable by others", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "[Interface]\nPrivateKey = secret\n" {
		t.Errorf("the old content was not replaced: %q", content)
	}
}

func TestWriteProfileCreatesAtZeroSixHundred(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "phone.conf")
	if err := writeProfile(path, "profile"); err != nil {
		t.Fatalf("writeProfile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 0600", got)
	}
}
