package bot

import (
	"context"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func TestLegacyRussianMessagesDoNotMixEnglishFragments(t *testing.T) {
	t.Parallel()

	t.Run("drift alert", func(t *testing.T) {
		operations := []domain.Operation{
			{Kind: domain.OpUpdate, Resource: domain.ResourceRef{Type: "peer", ID: "macbook"}, Reason: "key differs"},
			{Kind: domain.OpDelete, Resource: domain.ResourceRef{Type: "ingress", ID: "awg0"}, Reason: "stale"},
		}
		got := legacyRussianDriftAlert(operations)
		want := "⚠️ <b>Дрейф</b>: хост расходится с ревизией и не сходится сам (2 расхождения):\n" +
			" • <code>update peer/macbook: key differs</code>\n" +
			" • <code>delete ingress/awg0: stale</code>\n" +
			"Агент должен был устранить это за минуту; проверьте его журнал."
		assertLegacyRussianMessage(t, got, want, "discrepancies")
	})
}

func TestSubscriptionProgressIsLocalized(t *testing.T) {
	tests := []struct {
		locale Locale
		want   string
	}{
		{LocaleEnglish, "📡 <b>wg-nl</b>: checking candidate 2 of 3 in an isolated namespace…\n\nRejected (1):\n • <code>timeout</code>\n"},
		{LocaleRussian, "📡 <b>wg-nl</b>: проверяю кандидата 2 из 3 в изолированном namespace…\n\nОтклонены (1):\n • <code>timeout</code>\n"},
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

func assertLegacyRussianMessage(t *testing.T, got, want, englishFragment string) {
	t.Helper()
	if got != want {
		t.Fatalf("message mismatch:\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(got, englishFragment) {
		t.Fatalf("message contains mixed-language fragment %q: %q", englishFragment, got)
	}
}
