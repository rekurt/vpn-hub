package bot

import (
	"context"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

func TestLegacyRussianMessagesDoNotMixEnglishFragments(t *testing.T) {
	t.Parallel()

	t.Run("tunnel progress", func(t *testing.T) {
		got := legacyRussianTunnelTestProgress(2)
		want := "🩺 Проверяю 2 туннеля…"
		assertLegacyRussianMessage(t, got, want, "tunnels")
	})

	t.Run("subscription progress", func(t *testing.T) {
		instance, api := hubFixture(t)
		instance.progressEditor(context.Background(), adminID, 7, "wg-nl")(2, 3, []string{"timeout"})

		got := api.lastScreen(t).text
		want := "📡 <b>wg-nl</b>: проверяю кандидата 2 из 3 в изолированном namespace…\n\n" +
			"Отклонены (1):\n • <code>timeout</code>\n"
		assertLegacyRussianMessage(t, got, want, "Rejected")
	})

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

func assertLegacyRussianMessage(t *testing.T, got, want, englishFragment string) {
	t.Helper()
	if got != want {
		t.Fatalf("message mismatch:\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(got, englishFragment) {
		t.Fatalf("message contains mixed-language fragment %q: %q", englishFragment, got)
	}
}
