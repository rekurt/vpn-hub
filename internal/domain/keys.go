package domain

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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
