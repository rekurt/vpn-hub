// Package bot is the Telegram delivery: hubctl's operations behind a chat
// interface, plus the observability hubctl cannot give -- a CLI is silent between
// invocations, while the bot watches the journal, the state files and the tunnels
// and speaks up on its own.
package bot

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	configadapter "vpn-hub/internal/adapters/config"
)

// Config is the bot's own configuration: whose commands to obey and how often to
// look around. It lives beside the hub configuration, mode 0600, optionally
// SOPS-encrypted -- the token is a credential.
type Config struct {
	Token         string
	AdminID       int64
	Notifications Notifications
}

// Notifications sets the cadence of the bot's own observations.
type Notifications struct {
	// HealthInterval is how often every enabled tunnel is probed.
	HealthInterval time.Duration
	// DriftInterval is how often the desired state is compared with the host.
	DriftInterval time.Duration
	// SubscriptionRefresh is how often subscription tunnels are refreshed. The bot
	// is the scheduler on purpose: refreshes share the singleton canary namespace,
	// so they must all pass through the bot's one mutation gate.
	SubscriptionRefresh time.Duration
}

// LoadConfig reads the bot configuration, decrypting transparently when the file is
// a SOPS envelope. Unknown keys are rejected: a typo in `admin_id` must not become
// a bot that obeys nobody -- or anybody.
func LoadConfig(ctx context.Context, path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read bot configuration: %w", err)
	}
	if configadapter.IsEncrypted(content) {
		if content, err = (configadapter.SOPSSecretStore{}).Decrypt(ctx, path); err != nil {
			return Config{}, err
		}
	}

	var wire struct {
		Token         string `yaml:"token"`
		AdminID       int64  `yaml:"admin_id"`
		Notifications struct {
			HealthInterval      string `yaml:"health_interval"`
			DriftInterval       string `yaml:"drift_interval"`
			SubscriptionRefresh string `yaml:"subscription_refresh"`
		} `yaml:"notifications"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&wire); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	if wire.Token == "" {
		return Config{}, fmt.Errorf("%s: token is required", path)
	}
	if wire.AdminID == 0 {
		return Config{}, fmt.Errorf("%s: admin_id is required; @userinfobot tells you yours", path)
	}

	cfg := Config{Token: wire.Token, AdminID: wire.AdminID}
	intervals := []struct {
		name     string
		value    string
		fallback time.Duration
		into     *time.Duration
	}{
		{"health_interval", wire.Notifications.HealthInterval, 5 * time.Minute, &cfg.Notifications.HealthInterval},
		{"drift_interval", wire.Notifications.DriftInterval, 30 * time.Minute, &cfg.Notifications.DriftInterval},
		{"subscription_refresh", wire.Notifications.SubscriptionRefresh, 6 * time.Hour, &cfg.Notifications.SubscriptionRefresh},
	}
	for _, interval := range intervals {
		if interval.value == "" {
			*interval.into = interval.fallback
			continue
		}
		parsed, err := time.ParseDuration(interval.value)
		if err != nil || parsed <= 0 {
			return Config{}, fmt.Errorf("%s: %s %q is not a positive duration", path, interval.name, interval.value)
		}
		*interval.into = parsed
	}
	return cfg, nil
}
