package domain

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// The encoding is the whole point of these helpers existing separately: sing-box
// and every client application read base64url, while the hub's ordinary X25519
// helpers emit standard base64. A key in the wrong encoding still decodes to 32
// bytes, so only an explicit check catches the mix-up.
func TestGenerateRealityKeyPairIsBase64URL(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{"private": privateKey, "public": publicKey} {
		if strings.ContainsAny(key, "+/=") {
			t.Errorf("%s key %q carries standard-base64 characters", name, key)
		}
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			t.Errorf("%s key %q is not base64url: %v", name, key, err)
			continue
		}
		if len(raw) != KeyLength {
			t.Errorf("%s key decodes to %d bytes, want %d", name, len(raw), KeyLength)
		}
		if err := ValidateRealityKey(key); err != nil {
			t.Errorf("%s key does not validate: %v", name, err)
		}
	}

	derived, err := RealityPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if derived != publicKey {
		t.Fatalf("derived public key %q, want %q", derived, publicKey)
	}
}

func TestValidateRealityKeyRejectsStandardBase64(t *testing.T) {
	t.Parallel()
	// A standard-base64 key of the right length: the exact mistake worth catching.
	stdEncoded := base64.StdEncoding.EncodeToString(make([]byte, KeyLength))
	if err := ValidateRealityKey(stdEncoded); err == nil {
		t.Fatalf("%q was accepted as a reality key", stdEncoded)
	}
}

// Both derivations must be stable: the short id and every device's credential are
// recomputed on each reconcile, and a value that moved would silently lock out
// every client that had already imported its profile.
func TestRealityDerivationsAreStable(t *testing.T) {
	t.Parallel()
	const privateKey = "cGtxNTZKb0hRZHZKWXhpVGxDMFlpS3Y0dGRlbEVOSHU"
	publicKey, err := RealityPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if got := RealityShortID(publicKey); got != RealityShortID(publicKey) || len(got) != 16 {
		t.Fatalf("short id %q is unstable or the wrong length", got)
	}
	if _, err := base64.RawURLEncoding.DecodeString(publicKey); err != nil {
		t.Fatalf("derived public key is not base64url: %v", err)
	}

	first, err := RealityUserUUID(privateKey, "macbook")
	if err != nil {
		t.Fatal(err)
	}
	second, err := RealityUserUUID(privateKey, "macbook")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("the same device got two credentials: %q and %q", first, second)
	}

	other, err := RealityUserUUID(privateKey, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("two devices share one credential")
	}

	// Shaped as a version 4 UUID, since some clients reject anything else.
	uuidShape := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidShape.MatchString(first) {
		t.Fatalf("credential %q is not a version 4 UUID", first)
	}
}
