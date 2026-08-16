package runtime

import (
	"context"
	"fmt"
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

// Load returns the saved settings; a missing file is an empty value, not an error.
func (s BotSettingsStore) Load(_ context.Context) (BotSettings, error) {
	if s.StateDir == "" {
		return BotSettings{}, fmt.Errorf("state directory is required")
	}
	settings, _, err := readStateJSON[BotSettings](s.StateDir, botSettingsFile, "bot settings")
	return settings, err
}

func (s BotSettingsStore) Save(_ context.Context, settings BotSettings) error {
	return writeStateJSON(s.StateDir, botSettingsFile, "bot settings", settings)
}
