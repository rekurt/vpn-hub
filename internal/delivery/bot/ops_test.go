package bot

import (
	"sync"
	"testing"
)

// Exactly one contender wins the gate; the losers learn what it is busy with.
func TestGateAdmitsExactlyOne(t *testing.T) {
	t.Parallel()
	gate := &opsGate{}

	var mu sync.Mutex
	winners, busy := 0, 0
	var busyWith []string

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, current, ok := gate.Acquire("деплой")
			mu.Lock()
			defer mu.Unlock()
			if ok {
				winners++
				defer release()
				return
			}
			busy++
			busyWith = append(busyWith, current)
		}()
	}
	wg.Wait()

	if winners < 1 {
		t.Fatal("nobody won the gate")
	}
	if winners+busy != 8 {
		t.Fatalf("lost contenders: %d winners, %d busy", winners, busy)
	}
	for _, current := range busyWith {
		if current != "деплой" {
			t.Fatalf("a loser was told %q instead of the running operation", current)
		}
	}
}

func TestGateIsReusableAfterRelease(t *testing.T) {
	t.Parallel()
	gate := &opsGate{}
	release, _, ok := gate.Acquire("первая")
	if !ok {
		t.Fatal("fresh gate must admit")
	}
	release()
	release2, busyWith, ok := gate.Acquire("вторая")
	if !ok {
		t.Fatalf("released gate must admit again (busy with %q)", busyWith)
	}
	release2()
}
