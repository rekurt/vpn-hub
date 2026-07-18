package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"vpn-hub/internal/domain"
)

type ViperRepository struct {
	Path string
}

func (r ViperRepository) Load(_ context.Context) (domain.Config, error) {
	if r.Path == "" {
		return domain.Config{}, fmt.Errorf("configuration path is required")
	}

	v := viper.New()
	v.SetConfigFile(r.Path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("VPN_HUB")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		return domain.Config{}, fmt.Errorf("read %s: %w", r.Path, err)
	}

	// Reject unknown keys: a typo such as `dns_zone:` for `dns_zones:` would otherwise be
	// dropped silently, disabling the DNS-zone conflict checks for that tunnel.
	strict := func(config *mapstructure.DecoderConfig) { config.ErrorUnused = true }

	var cfg domain.Config
	if err := v.Unmarshal(&cfg, strict); err != nil {
		return domain.Config{}, fmt.Errorf("decode %s: %w", r.Path, err)
	}
	return cfg, nil
}
