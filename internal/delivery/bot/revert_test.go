package bot

import (
	"errors"
	"strings"
	"testing"

	"vpn-hub/internal/domain"
)

// Every configuration edit in the bot is a write-validate-revert dance, and each
// one used to drop the revert's own error and report "cancelled" regardless. That
// is a lie the operator acts on: the file is still broken, the next deploy fails
// validation, and the screen said the change had been taken back.
func TestRevertEditTellsTheTruthWhenTheUndoFails(t *testing.T) {
	t.Parallel()
	invalid := errors.New("device macbook has no way out")

	locales := []struct {
		locale          Locale
		cancelledMarker string
		brokenMarker    string
	}{
		{LocaleEnglish, "Change canceled", "remains invalid"},
		{LocaleRussian, "Изменение отменено", "осталась сломанной"},
	}
	for _, tt := range locales {
		t.Run(string(tt.locale), func(t *testing.T) {
			l, err := NewLocalizer(tt.locale)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("an undo that worked reports the cancellation", func(t *testing.T) {
				undone := false
				view := revertEdit(l, l.Text(msgRevertInvalidConfig), invalid, func() error {
					undone = true
					return nil
				})
				if !undone {
					t.Fatal("the change was not undone")
				}
				if !strings.Contains(view.text, tt.cancelledMarker) {
					t.Errorf("the operator was not told the change was taken back:\n%s", view.text)
				}
				if !strings.Contains(view.text, invalid.Error()) {
					t.Errorf("the reason is missing:\n%s", view.text)
				}
			})

			t.Run("an undo that failed says the file is still broken", func(t *testing.T) {
				undoErr := errors.New("read-only file system")
				view := revertEdit(l, l.Text(msgRevertInvalidConfig), invalid, func() error {
					return undoErr
				})
				if strings.Contains(view.text, tt.cancelledMarker) {
					t.Errorf("a failed undo was reported as a cancellation:\n%s", view.text)
				}
				if !strings.Contains(view.text, tt.brokenMarker) {
					t.Errorf("the operator was not told the configuration is still broken:\n%s", view.text)
				}
				if !strings.Contains(view.text, invalid.Error()) || !strings.Contains(view.text, undoErr.Error()) {
					t.Errorf("one of the two reasons is missing:\n%s", view.text)
				}
			})
		})
	}
}

// The hub carries the whole client prefix on its ingress interface, so the last
// IPv4 address in it is that link's broadcast address. Suggesting it would hand a
// device an address the kernel treats as broadcast -- reachable only when the
// prefix is nearly full, which is exactly when nobody is watching.
func TestNextFreeAddressSkipsNetworkAndBroadcast(t *testing.T) {
	t.Parallel()
	cfg := domain.Config{Hub: domain.Hub{ClientCIDR: "10.80.0.0/29", DNSAddress: "10.80.0.1"}}
	// .0 is the network, .1 the hub, .7 the broadcast: .2 through .6 are assignable.
	for _, taken := range []string{"10.80.0.2/32", "10.80.0.3/32", "10.80.0.4/32", "10.80.0.5/32"} {
		cfg.Devices = append(cfg.Devices, domain.Device{Address: taken})
	}
	if got := nextFreeAddress(cfg); got != "10.80.0.6/32" {
		t.Fatalf("nextFreeAddress = %q, want the last assignable address", got)
	}

	cfg.Devices = append(cfg.Devices, domain.Device{Address: "10.80.0.6/32"})
	if got := nextFreeAddress(cfg); got != "" {
		t.Errorf("nextFreeAddress = %q, want none: only the broadcast address is left", got)
	}
}
