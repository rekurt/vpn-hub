package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"vpn-hub/internal/domain"
)

func TestProfileKeyStoreSaveLoadAndPermissions(t *testing.T) {
	t.Parallel()
	privateKey, _, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store := ProfileKeyStore{StateDir: t.TempDir()}
	if err := store.Save(context.Background(), "macbook", privateKey); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background(), "macbook")
	if err != nil {
		t.Fatal(err)
	}
	if got != privateKey {
		t.Fatal("loaded private key differs")
	}
	info, err := os.Stat(filepath.Join(store.StateDir, profileKeysDir, "macbook.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("profile key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestProfileKeyStoreMissingAndUnsafeDeviceID(t *testing.T) {
	t.Parallel()
	store := ProfileKeyStore{StateDir: t.TempDir()}
	if _, err := store.Load(context.Background(), "missing"); !errors.Is(err, ErrProfileKeyNotFound) {
		t.Fatalf("missing key error = %v, want ErrProfileKeyNotFound", err)
	}
	if _, err := store.Load(context.Background(), "../outside"); err == nil {
		t.Fatal("path traversal device id was accepted")
	}
}
