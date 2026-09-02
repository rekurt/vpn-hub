package bot

import "fmt"

// Locale selects the language used for bot messages.
type Locale string

const (
	LocaleEnglish Locale = "en"
	LocaleRussian Locale = "ru"
)

// MessageID is a stable, locale-neutral identifier for a bot message.
type MessageID string

const (
	MsgMainTitle     MessageID = "main/title"
	MsgMainIntro     MessageID = "main/intro"
	MsgButtonStatus  MessageID = "button/status"
	MsgButtonDevices MessageID = "button/devices"
	MsgConfirmYes    MessageID = "confirm/yes"
	MsgConfirmNo     MessageID = "confirm/no"
)

// Catalog maps message identifiers to locale-specific format strings.
type Catalog map[MessageID]string

// Localizer renders bot messages in one immutable locale.
type Localizer struct {
	locale  Locale
	catalog Catalog
	strict  bool
}

// NewLocalizer returns a localizer for the requested language.
func NewLocalizer(locale Locale) (Localizer, error) {
	return newLocalizer(locale, false)
}

func newStrictLocalizer(locale Locale) (Localizer, error) {
	return newLocalizer(locale, true)
}

func newLocalizer(locale Locale, strict bool) (Localizer, error) {
	var err error
	locale, err = normalizeLocale(locale)
	if err != nil {
		return Localizer{}, err
	}

	var catalog Catalog
	switch locale {
	case LocaleEnglish:
		catalog = englishCatalog()
	case LocaleRussian:
		catalog = russianCatalog()
	}

	return Localizer{locale: locale, catalog: catalog, strict: strict}, nil
}

func normalizeLocale(locale Locale) (Locale, error) {
	if locale == "" {
		return LocaleEnglish, nil
	}
	switch locale {
	case LocaleEnglish, LocaleRussian:
		return locale, nil
	default:
		return "", unsupportedLocaleError(locale)
	}
}

func unsupportedLocaleError(locale Locale) error {
	return fmt.Errorf("locale %q is not supported; use en or ru", locale)
}

// Text renders a message using the supplied format arguments. A missing message
// identifier remains visible in production; strict localizers make test gaps fail.
func (l Localizer) Text(id MessageID, args ...any) string {
	text, ok := l.catalog[id]
	if !ok {
		if l.strict {
			panic(fmt.Sprintf("missing localized message %q", id))
		}
		return string(id)
	}
	return fmt.Sprintf(text, args...)
}

// Locale returns the language selected for this localizer.
func (l Localizer) Locale() Locale {
	return l.locale
}
