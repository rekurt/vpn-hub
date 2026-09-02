package bot

import (
	"regexp"
	"slices"
	"testing"
	"unicode"
)

func TestNewLocalizerSelectsCatalog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		locale Locale
		want   string
	}{
		{LocaleEnglish, "Management hub"},
		{LocaleRussian, "Центр управления"},
	}

	for _, tt := range tests {
		t.Run(string(tt.locale), func(t *testing.T) {
			l, err := NewLocalizer(tt.locale)
			if err != nil {
				t.Fatalf("NewLocalizer(%q): %v", tt.locale, err)
			}
			if got := l.Text(MsgMainTitle); got != tt.want {
				t.Fatalf("Text(%q) = %q, want %q", MsgMainTitle, got, tt.want)
			}
			if got := l.Locale(); got != tt.locale {
				t.Fatalf("Locale() = %q, want %q", got, tt.locale)
			}
		})
	}
}

func TestNewLocalizerRejectsUnsupportedLocale(t *testing.T) {
	t.Parallel()
	_, err := NewLocalizer(Locale("de"))
	if err == nil || err.Error() != `locale "de" is not supported; use en or ru` {
		t.Fatalf("NewLocalizer error = %v", err)
	}
}

func TestLocalizerTextFormatsArguments(t *testing.T) {
	t.Parallel()
	l := Localizer{catalog: Catalog{MessageID("test.value"): "Value: %d"}}
	if got := l.Text(MessageID("test.value"), 7); got != "Value: 7" {
		t.Fatalf("Text() = %q, want %q", got, "Value: 7")
	}
}

func TestLocalizerTextReturnsIDForMissingMessage(t *testing.T) {
	t.Parallel()
	l, err := NewLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Text(MessageID("missing.message")); got != "missing.message" {
		t.Fatalf("Text() = %q, want missing MessageID", got)
	}
}

func TestStrictLocalizerPanicsForMissingMessage(t *testing.T) {
	t.Parallel()
	l, err := newStrictLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Text did not panic for a missing MessageID")
		}
	}()
	l.Text(MessageID("missing.message"))
}

func TestNewLocalizerDoesNotShareMutableCatalog(t *testing.T) {
	t.Parallel()
	first, err := NewLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	first.catalog[MsgMainTitle] = "modified"

	second, err := NewLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Text(MsgMainTitle); got != "Management hub" {
		t.Fatalf("second localizer shared mutable state: %q", got)
	}
}

func TestCatalogsHaveParity(t *testing.T) {
	t.Parallel()
	english, russian := englishCatalog(), russianCatalog()
	if len(english) != len(russian) {
		t.Fatalf("catalog sizes differ: English=%d Russian=%d", len(english), len(russian))
	}
	for id, englishText := range english {
		russianText, ok := russian[id]
		if !ok {
			t.Errorf("Russian catalog is missing %q", id)
			continue
		}
		if englishText == "" || russianText == "" {
			t.Errorf("%q has an empty translation", id)
		}
		if got, want := formatVerbs(englishText), formatVerbs(russianText); !slices.Equal(got, want) {
			t.Errorf("%q placeholders = %v in English, %v in Russian", id, got, want)
		}
		for _, r := range englishText {
			if unicode.Is(unicode.Cyrillic, r) {
				t.Errorf("English translation %q contains Cyrillic: %q", id, englishText)
				break
			}
		}
	}
	for id := range russian {
		if _, ok := english[id]; !ok {
			t.Errorf("English catalog is missing %q", id)
		}
	}
}

var formatVerbPattern = regexp.MustCompile(`%(?:\[[0-9]+\])?[+#0\- ]*(?:[0-9]+|\*)?(?:\.(?:[0-9]+|\*))?[vTtbcdoOxXUeEfgGsqxXp]`)

func formatVerbs(text string) []string {
	matches := formatVerbPattern.FindAllString(text, -1)
	verbs := make([]string, 0, len(matches))
	for _, match := range matches {
		verbs = append(verbs, match[len(match)-1:])
	}
	return verbs
}

func TestFormatVerbsPreservesPlaceholderOrder(t *testing.T) {
	t.Parallel()
	got := formatVerbs("Device %s used %.1f%%")
	want := []string{"s", "f"}
	if !slices.Equal(got, want) {
		t.Fatalf("formatVerbs() = %v, want %v", got, want)
	}
}
