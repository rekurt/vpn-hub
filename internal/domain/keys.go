package domain

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateX25519KeyPair() (privateKey, publicKey string, err error) {
	private := make([]byte, 32)
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
