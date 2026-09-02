package bot

import (
	"os"
	"slices"
	"strings"
	"testing"
	"unicode"
)

func TestLocaleProductionSourcesContainNoUnexpectedCyrillic(t *testing.T) {
	t.Parallel()
	allowedUntilLaterTasks := map[string]bool{
		"notify.go": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "locale_ru.go" || allowedUntilLaterTasks[name] {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range string(body) {
			if unicode.Is(unicode.Cyrillic, value) {
				t.Errorf("%s contains Cyrillic outside the Russian catalog", name)
				break
			}
		}
	}
}

func TestCatalogMessageIDsAreNotDNSNames(t *testing.T) {
	t.Parallel()
	for id := range englishCatalog() {
		if strings.ContainsRune(string(id), '.') {
			t.Errorf("MessageID %q is DNS-like; use slash-delimited segments", id)
		}
	}
}

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
	l := Localizer{catalog: Catalog{MessageID("test_value"): "Value: %d"}}
	if got := l.Text(MessageID("test_value"), 7); got != "Value: 7" {
		t.Fatalf("Text() = %q, want %q", got, "Value: 7")
	}
}

func TestLocalizerTextReturnsIDForMissingMessage(t *testing.T) {
	t.Parallel()
	l, err := NewLocalizer(LocaleEnglish)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Text(MessageID("missing_message")); got != "missing_message" {
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
	l.Text(MessageID("missing_message"))
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
		if !catalogFormatsMatch(englishText, russianText) {
			t.Errorf("%q fmt directives differ: English=%q Russian=%q", id, englishText, russianText)
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

type formatArgument struct {
	role  byte
	index int
}

type formatDimension struct {
	present  bool
	argument bool
	literal  string
}

type formatDirective struct {
	escaped   bool
	verb      byte
	flags     string
	width     formatDimension
	precision formatDimension
	args      [3]formatArgument
	argsLen   int
}

func catalogFormatsMatch(english, russian string) bool {
	englishDirectives, ok := parseFormatDirectives(english)
	if !ok {
		return false
	}
	russianDirectives, ok := parseFormatDirectives(russian)
	return ok && slices.Equal(englishDirectives, russianDirectives)
}

func parseFormatDirectives(text string) ([]formatDirective, bool) {
	directives := make([]formatDirective, 0)
	nextArgument := 1
	for i := 0; i < len(text); i++ {
		if text[i] != '%' {
			continue
		}
		i++
		if i == len(text) {
			return nil, false
		}
		if text[i] == '%' {
			directives = append(directives, formatDirective{escaped: true})
			continue
		}

		directive := formatDirective{}
		if index, next, present, ok := parseOptionalFormatIndex(text, i); present {
			if !ok {
				return nil, false
			}
			nextArgument = index
			i = next
		}
		flagsStart := i
		for i < len(text) && isFormatFlag(text[i]) {
			i++
		}
		directive.flags = text[flagsStart:i]

		var ok bool
		directive.width, i, nextArgument, ok = parseFormatWidth(text, i, nextArgument, &directive)
		if !ok {
			return nil, false
		}
		if i < len(text) && text[i] == '.' {
			i++
			directive.precision, i, nextArgument, ok = parseFormatPrecision(text, i, nextArgument, &directive)
			if !ok {
				return nil, false
			}
		}

		if index, next, present, ok := parseOptionalFormatIndex(text, i); present {
			if !ok {
				return nil, false
			}
			nextArgument = index
			directive.addArgument('v', index)
			i = next
		} else {
			directive.addArgument('v', nextArgument)
		}
		if i == len(text) || !isFormatVerb(text[i]) {
			return nil, false
		}
		directive.verb = text[i]
		nextArgument++
		directives = append(directives, directive)
	}
	return directives, true
}

func parseFormatWidth(text string, start, nextArgument int, directive *formatDirective) (formatDimension, int, int, bool) {
	dimension := formatDimension{}
	if start == len(text) {
		return dimension, start, nextArgument, true
	}
	if text[start] == '*' {
		dimension = formatDimension{present: true, argument: true}
		directive.addArgument('w', nextArgument)
		return dimension, start + 1, nextArgument + 1, true
	}
	if index, next, present, ok := parseOptionalFormatIndex(text, start); present {
		if !ok || next == len(text) || text[next] != '*' {
			return formatDimension{}, start, nextArgument, false
		}
		dimension = formatDimension{present: true, argument: true}
		directive.addArgument('w', index)
		return dimension, next + 1, index + 1, true
	}
	end := start
	for end < len(text) && text[end] >= '0' && text[end] <= '9' {
		end++
	}
	if end != start {
		dimension.present = true
		dimension.literal = text[start:end]
	}
	return dimension, end, nextArgument, true
}

func parseFormatPrecision(text string, start, nextArgument int, directive *formatDirective) (formatDimension, int, int, bool) {
	if start == len(text) {
		return formatDimension{}, start, nextArgument, false
	}
	if text[start] == '*' {
		directive.addArgument('p', nextArgument)
		return formatDimension{present: true, argument: true}, start + 1, nextArgument + 1, true
	}
	if index, next, present, ok := parseOptionalFormatIndex(text, start); present {
		if !ok || next == len(text) || text[next] != '*' {
			return formatDimension{}, start, nextArgument, false
		}
		directive.addArgument('p', index)
		return formatDimension{present: true, argument: true}, next + 1, index + 1, true
	}
	end := start
	for end < len(text) && text[end] >= '0' && text[end] <= '9' {
		end++
	}
	if end == start {
		return formatDimension{}, start, nextArgument, false
	}
	return formatDimension{present: true, literal: text[start:end]}, end, nextArgument, true
}

func (d *formatDirective) addArgument(role byte, index int) {
	d.args[d.argsLen] = formatArgument{role: role, index: index}
	d.argsLen++
}

func parseOptionalFormatIndex(text string, start int) (index, next int, present, ok bool) {
	if start == len(text) || text[start] != '[' {
		return 0, start, false, true
	}
	i := start + 1
	if i == len(text) || text[i] < '1' || text[i] > '9' {
		return 0, start, true, false
	}
	index = 0
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		index = index*10 + int(text[i]-'0')
		i++
	}
	if i == len(text) || text[i] != ']' {
		return 0, start, true, false
	}
	return index, i + 1, true, true
}

func isFormatFlag(value byte) bool {
	return value == '#' || value == '0' || value == '+' || value == '-' || value == ' '
}

func isFormatVerb(value byte) bool {
	return value == 'v' || value == 'T' || value == 't' || value == 'b' || value == 'c' ||
		value == 'd' || value == 'o' || value == 'O' || value == 'q' || value == 'x' ||
		value == 'X' || value == 'U' || value == 'e' || value == 'E' || value == 'f' ||
		value == 'F' || value == 'g' || value == 'G' || value == 's' || value == 'p'
}

func TestCatalogFormatsMatchFullDirectiveStructure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		english string
		russian string
		want    bool
	}{
		{
			name:    "equivalent explicit argument positions",
			english: "%s %d%%",
			russian: "%[1]s %[2]d%%",
			want:    true,
		},
		{
			name:    "equivalent indexed width and precision arguments",
			english: "%*.*f",
			russian: "%[1]*.[2]*[3]f",
			want:    true,
		},
		{
			name:    "different positional order and missing escaped percent",
			english: "%[2]s %[1]d%%",
			russian: "%[1]s %[2]d",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := catalogFormatsMatch(tt.english, tt.russian); got != tt.want {
				t.Fatalf("catalogFormatsMatch(%q, %q) = %v, want %v", tt.english, tt.russian, got, tt.want)
			}
		})
	}
}

func TestParseFormatDirectivesAcceptsValidGrammar(t *testing.T) {
	t.Parallel()
	for _, format := range []string{
		"%s",
		"%[2]s",
		"%[2]+d",
		"%[2]05d",
		"%5.2f",
		"%*.*f",
		"%[2]*.[1]*[3]f",
		"%%",
	} {
		t.Run(format, func(t *testing.T) {
			if _, ok := parseFormatDirectives(format); !ok {
				t.Fatalf("parseFormatDirectives(%q) rejected valid format", format)
			}
		})
	}
}

func TestParseFormatDirectivesRejectsMalformedGrammar(t *testing.T) {
	t.Parallel()
	for _, format := range []string{
		"%",
		"%[",
		"%[]s",
		"%[0]s",
		"%[2",
		"%[a]s",
		"%.",
		"%.s",
		"%*.[2]f",
		"%[2]*.[1]f",
	} {
		t.Run(format, func(t *testing.T) {
			if _, ok := parseFormatDirectives(format); ok {
				t.Fatalf("parseFormatDirectives(%q) accepted malformed format", format)
			}
		})
	}
}
