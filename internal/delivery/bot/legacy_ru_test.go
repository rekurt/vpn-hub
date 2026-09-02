package bot

import (
	"context"
	"testing"
)

func TestSubscriptionProgressIsLocalized(t *testing.T) {
	tests := []struct {
		locale Locale
		want   string
	}{
		{LocaleEnglish, "📡 <b>wg-nl</b>: checking candidate 2 of 3 in an isolated namespace…\n\nRejected candidates: 1. Details are available in the bot service log.\n"},
		{LocaleRussian, "📡 <b>wg-nl</b>: проверяю кандидата 2 из 3 в изолированном namespace…\n\nОтклонено кандидатов: 1. Подробности доступны в журнале сервиса бота.\n"},
	}
	for _, tt := range tests {
		t.Run(string(tt.locale), func(t *testing.T) {
			instance, api := hubFixtureLocale(t, tt.locale)
			instance.progressEditor(context.Background(), adminID, 7, "wg-nl")(2, 3, []string{"timeout"})
			if got := api.lastScreen(t).text; got != tt.want {
				t.Fatalf("progress message = %q, want %q", got, tt.want)
			}
		})
	}
}
