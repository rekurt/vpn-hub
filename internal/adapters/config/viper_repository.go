package config

import (
	"context"
	"fmt"
	"strings"

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

	var cfg domain.Config
	if err := v.Unmarshal(&cfg); err != nil {
		return domain.Config{}, fmt.Errorf("decode %s: %w", r.Path, err)
	}
	return cfg, nil
}
