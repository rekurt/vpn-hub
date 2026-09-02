package bot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeBotConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telegram.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(context.Background(), writeBotConfig(t, "token: \"1:AA\"\nadmin_id: 42\n"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Token != "1:AA" || cfg.AdminID != 42 {
		t.Fatalf("unexpected config %+v", cfg)
	}
	if cfg.Locale != LocaleEnglish {
		t.Fatalf("Locale = %q, want %q", cfg.Locale, LocaleEnglish)
	}
	if cfg.Notifications.HealthInterval != 5*time.Minute ||
		cfg.Notifications.DriftInterval != 30*time.Minute ||
		cfg.Notifications.SubscriptionRefresh != 6*time.Hour {
		t.Fatalf("unexpected defaults %+v", cfg.Notifications)
	}
}

func TestLoadConfigLocale(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		body       string
		wantLocale Locale
		wantErr    string
	}{
		{"omitted defaults to English", "token: t\nadmin_id: 42\n", LocaleEnglish, ""},
		{"Russian accepted", "token: t\nadmin_id: 42\nlocale: ru\n", LocaleRussian, ""},
		{"unsupported rejected", "token: t\nadmin_id: 42\nlocale: de\n", "", `locale "de" is not supported; use en or ru`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(context.Background(), writeBotConfig(t, tc.body))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadConfig error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.Locale != tc.wantLocale {
				t.Fatalf("Locale = %q, want %q", cfg.Locale, tc.wantLocale)
			}
		})
	}
}

func TestLoadConfigParsesIntervals(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(context.Background(), writeBotConfig(t, `token: "1:AA"
admin_id: 42
notifications:
  health_interval: 1m
  drift_interval: 10m
  subscription_refresh: 12h
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Notifications.HealthInterval != time.Minute ||
		cfg.Notifications.DriftInterval != 10*time.Minute ||
		cfg.Notifications.SubscriptionRefresh != 12*time.Hour {
		t.Fatalf("unexpected intervals %+v", cfg.Notifications)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"no token":      "admin_id: 42\n",
		"no admin":      "token: \"1:AA\"\n",
		"unknown key":   "token: \"1:AA\"\nadmin_id: 42\nadmin_ids: [1]\n",
		"bad interval":  "token: \"1:AA\"\nadmin_id: 42\nnotifications: {health_interval: fast}\n",
		"zero interval": "token: \"1:AA\"\nadmin_id: 42\nnotifications: {drift_interval: 0s}\n",
	}
	for name, body := range cases {
		if _, err := LoadConfig(context.Background(), writeBotConfig(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A typo in admin_id must fail loudly, not become a bot that ignores its admin.
func TestLoadConfigErrorNamesTheFile(t *testing.T) {
	t.Parallel()
	path := writeBotConfig(t, "token: \"1:AA\"\n")
	_, err := LoadConfig(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "admin_id") {
		t.Fatalf("expected admin_id in the error, got %v", err)
	}
}
