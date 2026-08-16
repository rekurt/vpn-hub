package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

// Both key stores answer the same three questions -- read it, make it, refuse to
// replace it -- so both are driven through the same table. The REALITY one had no
// test at all, and it is the file every issued vless:// link derives from.
func TestKeyFilesReadCreateAndRefuseToClobber(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		create   func(path string) (string, error)
		read     func(path string) (string, error)
		validate func(string) error
		// clobbered is what the refusal must warn about losing.
		clobbered string
	}{
		"hub key": {
			create: func(path string) (string, error) { return ServerKeyFile{Path: path}.Create() },
			read: func(path string) (string, error) {
				return ServerKeyFile{Path: path}.PrivateKey(context.Background())
			},
			validate:  func(key string) error { _, err := domain.PublicKeyFromPrivate(key); return err },
			clobbered: "client profile",
		},
		"REALITY key": {
			create: func(path string) (string, error) { return RealityKeyFile{Path: path}.Create() },
			read: func(path string) (string, error) {
				return RealityKeyFile{Path: path}.PrivateKey(context.Background())
			},
			validate:  domain.ValidateRealityKey,
			clobbered: "issued link",
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// A directory that does not exist yet: creating one is part of the job.
			path := filepath.Join(t.TempDir(), "keys", "key")

			public, err := test.create(path)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if public == "" {
				t.Fatal("no public key was returned to put in the configuration")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("mode = %o, want 0600: this is a private key", mode)
			}

			private, err := test.read(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if err := test.validate(private); err != nil {
				t.Errorf("the key that was written does not validate: %v", err)
			}

			// Replacing it would invalidate everything already issued from it, so the
			// refusal has to say so rather than just fail.
			if _, err := test.create(path); err == nil {
				t.Fatal("an existing key was overwritten")
			} else if !strings.Contains(err.Error(), test.clobbered) {
				t.Errorf("the refusal does not say what would be lost: %v", err)
			}
			if again, err := test.read(path); err != nil || again != private {
				t.Errorf("the key changed despite the refusal: %v", err)
			}
		})
	}
}

func TestKeyFileReportsWhatToDoAboutAMissingKey(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "absent.key")

	_, err := ServerKeyFile{Path: missing}.PrivateKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "hubctl keygen") {
		t.Errorf("the hub key error does not say how to make one: %v", err)
	}
	_, err = RealityKeyFile{Path: missing}.PrivateKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--reality") {
		t.Errorf("the REALITY key error does not say how to make one: %v", err)
	}
}

// A key that is on disk but not usable is worth its own message: it is the shape
// of a hand-edited file, and "unusable" is the only thing that distinguishes it
// from one that is simply absent.
func TestKeyFileRefusesAnUnusableKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "broken.key")
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := (ServerKeyFile{Path: path}).PrivateKey(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "unusable") {
		t.Errorf("hub key: %v", err)
	}
	if _, err := (RealityKeyFile{Path: path}).PrivateKey(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "unusable") {
		t.Errorf("REALITY key: %v", err)
	}
}
