package bot

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

const (
	leakySubscriptionURL    = "https://provider.example.test/feed?token=SUPERSECRET"
	leakySubscriptionDetail = "dial tcp: lookup provider.example.test: transport refused"
)

func TestCandidateViewRedactsSubscriptionTransportErrors(t *testing.T) {
	for _, tt := range subscriptionLeakLocales() {
		t.Run(string(tt.locale), func(t *testing.T) {
			instance, api := hubFixtureLocale(t, tt.locale)
			makeFixtureTunnelSubscription(t, instance, leakySubscriptionURL)
			var logs bytes.Buffer
			instance.Out = &logs
			instance.Fetch = func(context.Context, string) ([]byte, error) {
				return nil, &url.Error{Op: "Get", URL: leakySubscriptionURL, Err: errors.New(leakySubscriptionDetail)}
			}

			instance.handleUpdate(context.Background(), tap(adminID, "sub:cand:wg-nl"))
			instance.wg.Wait()

			assertSubscriptionTextsRedacted(t, apiTexts(api), tt.safeFetch, tt.otherLanguage)
			assertRawSubscriptionErrorLogged(t, logs.String())
		})
	}
}

func TestManualRefreshRedactsProgressAndTerminalErrors(t *testing.T) {
	for _, tt := range subscriptionLeakLocales() {
		t.Run(string(tt.locale), func(t *testing.T) {
			instance, api := hubFixtureLocale(t, tt.locale)
			makeFixtureTunnelSubscription(t, instance, leakySubscriptionURL)
			var logs bytes.Buffer
			instance.Out = &logs
			instance.Refresh = func(_ context.Context, _ domain.Tunnel, progress func(int, int, []string)) (domain.ProxyTunnel, []string, error) {
				rejected := []string{leakySubscriptionDetail + " via " + leakySubscriptionURL}
				progress(1, 2, rejected)
				return domain.ProxyTunnel{}, rejected, &url.Error{Op: "Get", URL: leakySubscriptionURL, Err: errors.New(leakySubscriptionDetail)}
			}

			instance.handleUpdate(context.Background(), tap(adminID, "sub:r:wg-nl"))
			instance.wg.Wait()

			assertSubscriptionTextsRedacted(t, apiTexts(api), tt.safeFetch, tt.otherLanguage)
			assertRawSubscriptionErrorLogged(t, logs.String())
		})
	}
}

func TestScheduledRefreshRedactsSubscriptionTransportErrors(t *testing.T) {
	for _, tt := range subscriptionLeakLocales() {
		t.Run(string(tt.locale), func(t *testing.T) {
			instance, _ := hubFixtureLocale(t, tt.locale)
			var logs bytes.Buffer
			instance.Out = &logs
			instance.Refresh = func(context.Context, domain.Tunnel, func(int, int, []string)) (domain.ProxyTunnel, []string, error) {
				return domain.ProxyTunnel{}, []string{leakySubscriptionDetail + " via " + leakySubscriptionURL},
					&url.Error{Op: "Get", URL: leakySubscriptionURL, Err: errors.New(leakySubscriptionDetail)}
			}

			instance.refreshScheduled(context.Background(), domain.Tunnel{
				ID: "wg-nl",
				Source: domain.TunnelSource{
					Kind:  domain.SourceSubscription,
					Value: leakySubscriptionURL,
				},
			})

			ev := <-instance.events
			assertSubscriptionTextsRedacted(t, []string{ev.text}, tt.safeFetch, tt.otherLanguage)
			assertRawSubscriptionErrorLogged(t, logs.String())
		})
	}
}

func TestSubscriptionFailureKindsAreLocalizedAndEscaped(t *testing.T) {
	tests := []struct {
		kind    subscriptionFailureKind
		english string
		russian string
	}{
		{subscriptionFailureFetch, "The subscription could not be downloaded.", "Не удалось скачать подписку."},
		{subscriptionFailureParse, "The subscription response could not be parsed.", "Не удалось разобрать ответ подписки."},
		{subscriptionFailureNoCandidates, "The subscription contains no supported candidates.", "В подписке нет поддерживаемых кандидатов."},
		{subscriptionFailureValidation, "The subscription candidates failed endpoint validation.", "Кандидаты подписки не прошли проверку адресов."},
		{subscriptionFailureProbe, "No candidate passed the connectivity check.", "Ни один кандидат не прошёл проверку подключения."},
		{subscriptionFailureStore, "The selected candidate could not be saved.", "Не удалось сохранить выбранного кандидата."},
		{subscriptionFailureUnknown, "The subscription refresh failed.", "Не удалось обновить подписку."},
	}

	for _, locale := range []Locale{LocaleEnglish, LocaleRussian} {
		locale := locale
		t.Run(string(locale), func(t *testing.T) {
			l, err := newStrictLocalizer(locale)
			if err != nil {
				t.Fatal(err)
			}
			for _, tt := range tests {
				text, _ := renderRefreshFailure(l, "sub<&", 2, tt.kind)
				want := tt.english
				other := tt.russian
				if locale == LocaleRussian {
					want, other = tt.russian, tt.english
				}
				if !strings.Contains(text, want) || strings.Contains(text, other) {
					t.Errorf("kind %d text is missing or mixed: %q", tt.kind, text)
				}
				if !strings.Contains(text, "sub&lt;&amp;") || strings.Contains(text, "sub<&") {
					t.Errorf("kind %d tunnel ID was not HTML-escaped: %q", tt.kind, text)
				}
			}
		})
	}
}

func TestRenderFailureRedactsTypedSubscriptionError(t *testing.T) {
	for _, tt := range subscriptionLeakLocales() {
		t.Run(string(tt.locale), func(t *testing.T) {
			l, err := newStrictLocalizer(tt.locale)
			if err != nil {
				t.Fatal(err)
			}
			view := renderFailure(l, "unsafe wrapper", categorizeSubscriptionError(
				subscriptionFailureFetch,
				&url.Error{Op: "Get", URL: leakySubscriptionURL, Err: errors.New(leakySubscriptionDetail)},
			))
			assertSubscriptionTextsRedacted(t, []string{view.text}, tt.safeFetch, tt.otherLanguage)
		})
	}
}

func TestSubscriptionStageClassificationOverridesTransportShape(t *testing.T) {
	transport := &url.Error{Op: "Get", URL: leakySubscriptionURL, Err: errors.New(leakySubscriptionDetail)}
	for _, kind := range []subscriptionFailureKind{
		subscriptionFailureFetch,
		subscriptionFailureParse,
		subscriptionFailureNoCandidates,
		subscriptionFailureValidation,
		subscriptionFailureProbe,
		subscriptionFailureStore,
	} {
		if got := subscriptionFailureKindFor(categorizeSubscriptionError(kind, transport)); got != kind {
			t.Errorf("categorized transport error = %d, want stage %d", got, kind)
		}
	}
	if got := subscriptionFailureKindFor(transport); got != subscriptionFailureFetch {
		t.Errorf("untyped URL error = %d, want safe fetch fallback", got)
	}
}

type subscriptionLeakLocale struct {
	locale        Locale
	safeFetch     string
	otherLanguage string
}

func subscriptionLeakLocales() []subscriptionLeakLocale {
	return []subscriptionLeakLocale{
		{LocaleEnglish, "The subscription could not be downloaded.", "Не удалось скачать подписку."},
		{LocaleRussian, "Не удалось скачать подписку.", "The subscription could not be downloaded."},
	}
}

func makeFixtureTunnelSubscription(t *testing.T, instance *Bot, source string) {
	t.Helper()
	body := strings.Replace(read(t, instance.ConfigPath),
		"    source: {kind: config, value: \"wg-nl.conf\"}",
		"    source: {kind: subscription, value: \""+source+"\"}", 1)
	body = strings.Replace(body, "type: wireguard", "type: xray", 1)
	if err := os.WriteFile(instance.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func apiTexts(api *fakeAPI) []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	texts := make([]string, len(api.screens))
	for index, item := range api.screens {
		texts[index] = item.text
	}
	return texts
}

func assertSubscriptionTextsRedacted(t *testing.T, texts []string, safeCategory, otherLanguage string) {
	t.Helper()
	joined := strings.Join(texts, "\n")
	for _, secret := range []string{"SUPERSECRET", leakySubscriptionURL, leakySubscriptionDetail, "provider.example.test"} {
		if strings.Contains(joined, secret) {
			t.Errorf("Telegram text leaked %q:\n%s", secret, joined)
		}
	}
	if !strings.Contains(joined, safeCategory) {
		t.Errorf("Telegram text does not contain localized safe category %q:\n%s", safeCategory, joined)
	}
	if strings.Contains(joined, otherLanguage) {
		t.Errorf("Telegram text mixes locales via %q:\n%s", otherLanguage, joined)
	}
}

func assertRawSubscriptionErrorLogged(t *testing.T, logs string) {
	t.Helper()
	for _, detail := range []string{leakySubscriptionURL, "SUPERSECRET", leakySubscriptionDetail} {
		if !strings.Contains(logs, detail) {
			t.Errorf("server log does not contain raw subscription error detail %q:\n%s", detail, logs)
		}
	}
}
