package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The bot restarts on every deploy, so anything the admin tuned has to come back
// afterwards -- which is the whole reason this file exists and the reason an
// untested round trip was worth closing.
func TestBotSettingsSurviveARestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := BotSettingsStore{StateDir: dir}
	ctx := context.Background()

	// A hub that has never had its notifications touched.
	settings, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load before anything was saved: %v", err)
	}
	if len(settings.Alerts) != 0 {
		t.Errorf("a fresh hub reported saved settings: %v", settings.Alerts)
	}

	if err := store.Save(ctx, BotSettings{Alerts: map[string]bool{"drift": false, "health": true}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	restored, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if restored.Alerts["drift"] || !restored.Alerts["health"] {
		t.Errorf("settings did not survive: %v", restored.Alerts)
	}

	// The file carries no secret, but it lives beside ones that do and is written
	// through the same path; 0600 is what that path promises.
	info, err := os.Stat(filepath.Join(dir, botSettingsFile))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
}

func TestBotSettingsRefuseAnUnsetStateDirectory(t *testing.T) {
	t.Parallel()
	store := BotSettingsStore{}
	if _, err := store.Load(context.Background()); err == nil {
		t.Error("a store with nowhere to read from reported success")
	}
	if err := store.Save(context.Background(), BotSettings{}); err == nil {
		t.Error("a store with nowhere to write to reported success")
	}
}

// A file someone edited by hand is a failure to report, not an empty value to
// carry on with: silently resetting every alert to its default would be a change
// nobody asked for.
func TestBotSettingsReportBrokenJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, botSettingsFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (BotSettingsStore{StateDir: dir}).Load(context.Background()); err == nil {
		t.Error("a corrupt settings file was read as empty settings")
	}
}
