package runtime

import "testing"

func TestOffsetRoundTrip(t *testing.T) {
	t.Parallel()
	store := OffsetStore{StateDir: t.TempDir()}

	// A missing file means "start from the beginning", not an error.
	offset, err := store.Load()
	if err != nil || offset != 0 {
		t.Fatalf("fresh store: %d %v", offset, err)
	}

	if err := store.Save(918273645); err != nil {
		t.Fatalf("Save: %v", err)
	}
	offset, err = store.Load()
	if err != nil || offset != 918273645 {
		t.Fatalf("Load: %d %v", offset, err)
	}
}
