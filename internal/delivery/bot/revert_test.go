package bot

import (
	"errors"
	"strings"
	"testing"
)

// Every configuration edit in the bot is a write-validate-revert dance, and each
// one used to drop the revert's own error and report "cancelled" regardless. That
// is a lie the operator acts on: the file is still broken, the next deploy fails
// validation, and the screen said the change had been taken back.
func TestRevertEditTellsTheTruthWhenTheUndoFails(t *testing.T) {
	t.Parallel()
	invalid := errors.New("device macbook has no way out")

	t.Run("an undo that worked reports the cancellation", func(t *testing.T) {
		t.Parallel()
		undone := false
		view := revertEdit("отменено: конфигурация не проходит проверку", invalid, func() error {
			undone = true
			return nil
		})
		if !undone {
			t.Fatal("the change was not undone")
		}
		if !strings.Contains(view.text, "отменено") {
			t.Errorf("the operator was not told the change was taken back:\n%s", view.text)
		}
		if !strings.Contains(view.text, invalid.Error()) {
			t.Errorf("the reason is missing:\n%s", view.text)
		}
	})

	t.Run("an undo that failed says the file is still broken", func(t *testing.T) {
		t.Parallel()
		undoErr := errors.New("read-only file system")
		view := revertEdit("отменено: конфигурация не проходит проверку", invalid, func() error {
			return undoErr
		})
		if strings.Contains(view.text, "отменено") {
			t.Errorf("a failed undo was reported as a cancellation:\n%s", view.text)
		}
		if !strings.Contains(view.text, "сломанной") {
			t.Errorf("the operator was not told the configuration is still broken:\n%s", view.text)
		}
		// Both halves matter: what the change broke, and why it could not be undone.
		if !strings.Contains(view.text, invalid.Error()) || !strings.Contains(view.text, undoErr.Error()) {
			t.Errorf("one of the two reasons is missing:\n%s", view.text)
		}
	})
}
