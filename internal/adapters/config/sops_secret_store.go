package config

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// SOPSSecretStore delegates decryption to the audited sops CLI. The age key is
// intentionally resolved by sops and never accepted through Cobra or Viper.
type SOPSSecretStore struct {
	Binary string
}

func (s SOPSSecretStore) binary() string {
	if s.Binary != "" {
		return s.Binary
	}
	return "sops"
}

func (s SOPSSecretStore) Decrypt(ctx context.Context, path string) ([]byte, error) {
	command := exec.CommandContext(ctx, s.binary(), "--decrypt", path)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		// sops explains refusals precisely -- wrong key, not encrypted, bad format --
		// and discarding that leaves only "exit status 1".
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("decrypt %s: %w: %s", path, err, message)
		}
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}
	return stdout.Bytes(), nil
}

// IsEncrypted reports whether content looks like a SOPS envelope.
//
// Deciding by content rather than by filename means an operator can encrypt a file
// in place without renaming it, and cannot accidentally ship a plaintext file that
// the name claims is encrypted.
func IsEncrypted(content []byte) bool {
	return bytes.Contains(content, []byte("sops")) &&
		(bytes.Contains(content, []byte("ENC[")) || bytes.Contains(content, []byte("\"mac\"")) ||
			bytes.Contains(content, []byte("mac=")))
}
