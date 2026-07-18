package config

import (
	"context"
	"fmt"
	"os/exec"
)

// SOPSSecretStore delegates decryption to the audited sops CLI. The age key is
// intentionally resolved by sops and never accepted through Cobra or Viper.
type SOPSSecretStore struct {
	Binary string
}

func (s SOPSSecretStore) Decrypt(ctx context.Context, path string) ([]byte, error) {
	binary := s.Binary
	if binary == "" {
		binary = "sops"
	}
	output, err := exec.CommandContext(ctx, binary, "--decrypt", path).Output()
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}
	return output, nil
}
