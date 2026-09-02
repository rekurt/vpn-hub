package bot

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

// Exactly one contender wins the gate; the losers learn what it is busy with.
func TestGateAdmitsExactlyOne(t *testing.T) {
	t.Parallel()
	gate := &opsGate{}

	var mu sync.Mutex
	winners, busy := 0, 0
	var busyWith []operation

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, current, ok := gate.Acquire(newOperation(msgOperationDeploy))
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
		if !reflect.DeepEqual(current, newOperation(msgOperationDeploy)) {
			t.Fatalf("a loser was told %+v instead of the running operation", current)
		}
	}
}

func TestGateIsReusableAfterRelease(t *testing.T) {
	t.Parallel()
	gate := &opsGate{}
	release, _, ok := gate.Acquire(newOperation(msgOperationDeploy))
	if !ok {
		t.Fatal("fresh gate must admit")
	}
	release()
	release2, busyWith, ok := gate.Acquire(newOperation(msgOperationDeployRollback))
	if !ok {
		t.Fatalf("released gate must admit again (busy with %+v)", busyWith)
	}
	release2()
}

func TestGateOperationIdentityIsLocaleNeutral(t *testing.T) {
	t.Parallel()
	var currentByLocale []operation
	for _, locale := range []Locale{LocaleEnglish, LocaleRussian} {
		instance, _ := hubFixtureLocale(t, locale)
		running := newOperation(msgOperationHubKeyRotation)
		release, _, ok := instance.gate.Acquire(running)
		if !ok {
			t.Fatal("fresh gate must admit")
		}
		_, current, ok := instance.gate.Acquire(newOperation(msgOperationDeploy))
		if ok {
			t.Fatal("busy gate admitted a contender")
		}
		currentByLocale = append(currentByLocale, current)
		release()
	}
	if !reflect.DeepEqual(currentByLocale[0], currentByLocale[1]) {
		t.Fatalf("operation identity depends on locale: English=%+v Russian=%+v", currentByLocale[0], currentByLocale[1])
	}
}

func TestBusyOperationNameIsLocalizedAtDisplayTime(t *testing.T) {
	tests := []struct {
		locale Locale
		want   string
	}{
		{LocaleEnglish, "⏳ Busy: rotating hub key"},
		{LocaleRussian, "⏳ Занято: ротация ключа хаба"},
	}
	for _, tt := range tests {
		t.Run(string(tt.locale), func(t *testing.T) {
			instance, api := hubFixtureLocale(t, tt.locale)
			ctx := context.Background()
			instance.handleUpdate(ctx, tap(adminID, "dev:rv:macbook"))
			confirmation := api.lastScreen(t)

			release, _, ok := instance.gate.Acquire(newOperation(msgOperationHubKeyRotation))
			if !ok {
				t.Fatal("fresh gate must admit")
			}
			defer release()
			instance.handleUpdate(ctx, tap(adminID, "dev:rv!:macbook"))

			if got := lastToast(t, api); got != tt.want {
				t.Fatalf("busy toast = %q, want %q", got, tt.want)
			}
			if got := screenCallbackData(api.lastScreen(t).markup); !reflect.DeepEqual(got, screenCallbackData(confirmation.markup)) {
				t.Fatalf("busy operation changed callbacks: before=%v after=%v", screenCallbackData(confirmation.markup), got)
			}
			revoked, err := instance.Revocations.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(revoked) != 0 {
				t.Fatalf("busy operation changed revocations: %v", revoked)
			}
		})
	}
}
