package domain

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// KeyLength is the size of an X25519 key in bytes, before base64 encoding.
const KeyLength = 32

// ValidatePublicKey reports whether value is a base64-encoded X25519 public key.
// Public keys arrive from configuration and are never derived locally, so nothing
// else checks their shape.
func ValidatePublicKey(value string) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("key %q is not valid base64", value)
	}
	if len(raw) != KeyLength {
		return fmt.Errorf("key %q decodes to %d bytes, want %d", value, len(raw), KeyLength)
	}
	return nil
}

func GenerateX25519KeyPair() (privateKey, publicKey string, err error) {
	private := make([]byte, KeyLength)
	if _, err = rand.Read(private); err != nil {
		return "", "", fmt.Errorf("read randomness: %w", err)
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return "", "", fmt.Errorf("build x25519 private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func PublicKeyFromPrivate(privateKey string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode x25519 private key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(bytes)
	if err != nil {
		return "", fmt.Errorf("read x25519 private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// REALITY keys are the same X25519 keys as everywhere else, but encoded
// base64-RawURL rather than standard base64 -- that is the form sing-box and every
// client application read and write. Mixing the two encodings produces a key that
// looks right, decodes to 32 bytes, and never completes a handshake, which is the
// most expensive kind of wrong. They therefore get their own functions rather than
// a flag on the existing ones.

func GenerateRealityKeyPair() (privateKey, publicKey string, err error) {
	private := make([]byte, KeyLength)
	if _, err = rand.Read(private); err != nil {
		return "", "", fmt.Errorf("read randomness: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return "", "", fmt.Errorf("build x25519 private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func RealityPublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode reality private key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("read reality private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func ValidateRealityKey(value string) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("reality key is not base64url: %w", err)
	}
	if len(raw) != KeyLength {
		return fmt.Errorf("reality key decodes to %d bytes, want %d", len(raw), KeyLength)
	}
	return nil
}

// RealityShortID derives the handshake's short id from the public key.
//
// It is derived rather than configured because it is not a secret -- it travels in
// every client URI -- and one less thing in hub.yaml is one less thing to get
// wrong. Deriving it from the public key also means rotating the key rotates it.
func RealityShortID(publicKey string) string {
	digest := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(digest[:])[:16]
}

// RealityUserUUID derives a device's VLESS credential from the hub's private key.
//
// Derived, so nothing new has to be stored, backed up or kept in step with the
// device list: the credential exists wherever the private key does. Revocation
// still works, because a device removed from the revision is a user the rendered
// server configuration no longer contains.
func RealityUserUUID(privateKey, deviceID string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode reality private key: %w", err)
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte("vpn-hub/reality-user/" + deviceID))
	sum := mac.Sum(nil)

	// Shaped as a version 4 UUID: the value is derived, but every client parses it
	// as a UUID and some reject one whose version and variant bits are wrong.
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]), nil
}
