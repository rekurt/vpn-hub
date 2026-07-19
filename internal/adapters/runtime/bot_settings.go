package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const botSettingsFile = "bot-settings.json"

// BotSettings is what the bot's admin tuned at runtime and expects to survive a
// restart -- and the bot restarts on every deploy.
type BotSettings struct {
	// Alerts maps a notification category to whether it is delivered.
	Alerts map[string]bool `json:"alerts"`
}

// BotSettingsStore persists BotSettings in the state directory.
type BotSettingsStore struct {
	StateDir string
}

func (s BotSettingsStore) path() string {
	return filepath.Join(s.StateDir, botSettingsFile)
}

// Load returns the saved settings; a missing file is an empty value, not an error.
func (s BotSettingsStore) Load(_ context.Context) (BotSettings, error) {
	if s.StateDir == "" {
		return BotSettings{}, fmt.Errorf("state directory is required")
	}
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return BotSettings{}, nil
	}
	if err != nil {
		return BotSettings{}, fmt.Errorf("read bot settings: %w", err)
	}
	var settings BotSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return BotSettings{}, fmt.Errorf("decode bot settings: %w", err)
	}
	return settings, nil
}

func (s BotSettingsStore) Save(_ context.Context, settings BotSettings) error {
	if s.StateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	release, err := lockStateDir(s.StateDir)
	if err != nil {
		return err
	}
	defer release()

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bot settings: %w", err)
	}
	return atomicWrite(s.path(), data, 0o600)
}
