package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

type cancelAtContextCheck struct {
	context.Context
	check    int
	cancelAt int
	err      error
}

func (c *cancelAtContextCheck) Err() error {
	c.check++
	if c.check >= c.cancelAt {
		return c.err
	}
	return nil
}

func upstreamFixture(t *testing.T) (UpstreamFile, domain.Tunnel) {
	t.Helper()
	store := UpstreamFile{Dir: t.TempDir()}
	tunnel := domain.Tunnel{ID: "xray-de", Source: domain.TunnelSource{Kind: domain.SourceSubscription, Value: "https://provider.example/sub"}}
	return store, tunnel
}

func proxy(server string) domain.ProxyTunnel {
	return domain.ProxyTunnel{Protocol: "vless", Server: server, Port: 443, UUID: "3b1c8a52-4b6e-4d8a-9f00-0123456789ab"}
}

func TestCurrentReportsWhatWasWritten(t *testing.T) {
	t.Parallel()
	store, tunnel := upstreamFixture(t)

	if _, hasCurrent, hasPrevious := store.Current(tunnel.ID); hasCurrent || hasPrevious {
		t.Fatal("a fresh store must report nothing")
	}

	if err := store.Write(context.Background(), tunnel, proxy("1.2.3.4")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	current, hasCurrent, hasPrevious := store.Current(tunnel.ID)
	if !hasCurrent || current.Server != "1.2.3.4" || hasPrevious {
		t.Fatalf("unexpected state: %+v %v %v", current, hasCurrent, hasPrevious)
	}

	// A second write demotes the first to last-known-good.
	if err := store.Write(context.Background(), tunnel, proxy("5.6.7.8")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	current, _, hasPrevious = store.Current(tunnel.ID)
	if current.Server != "5.6.7.8" || !hasPrevious {
		t.Fatalf("unexpected state after second write: %+v %v", current, hasPrevious)
	}
}

func TestUpstreamWriteDoesNotStartAfterContextEnds(t *testing.T) {
	for name, setup := range map[string]func() (context.Context, context.CancelFunc, error){
		"cancellation": func() (context.Context, context.CancelFunc, error) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}, context.Canceled
		},
		"deadline": func() (context.Context, context.CancelFunc, error) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			return ctx, cancel, context.DeadlineExceeded
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, tunnel := upstreamFixture(t)
			ctx, cancel, wantErr := setup()
			defer cancel()

			err := store.Write(ctx, tunnel, proxy("5.6.7.8"))
			if !errors.Is(err, wantErr) {
				t.Fatalf("Write error = %v, want %v", err, wantErr)
			}
			if _, hasCurrent, hasPrevious := store.Current(tunnel.ID); hasCurrent || hasPrevious {
				t.Fatal("expired write changed subscription state")
			}
		})
	}
}

func TestUpstreamWriteStopsBetweenLastKnownGoodAndActiveCommit(t *testing.T) {
	for name, contextErr := range map[string]error{
		"cancellation": context.Canceled,
		"deadline":     context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			store, tunnel := upstreamFixture(t)
			if err := store.Write(context.Background(), tunnel, proxy("1.2.3.4")); err != nil {
				t.Fatalf("seed active upstream: %v", err)
			}
			ctx := &cancelAtContextCheck{Context: context.Background(), cancelAt: 4, err: contextErr}

			err := store.Write(ctx, tunnel, proxy("5.6.7.8"))
			if !errors.Is(err, contextErr) {
				t.Fatalf("Write error = %v, want %v", err, contextErr)
			}
			current, hasCurrent, hasPrevious := store.Current(tunnel.ID)
			if !hasCurrent || current.Server != "1.2.3.4" || !hasPrevious {
				t.Fatalf("unsafe partial commit: current=%+v hasCurrent=%v hasPrevious=%v", current, hasCurrent, hasPrevious)
			}
		})
	}
}

// Restore swaps the two links, so going back is itself reversible.
func TestRestoreSwapsWithLastKnownGood(t *testing.T) {
	t.Parallel()
	store, tunnel := upstreamFixture(t)
	ctx := context.Background()

	if _, err := store.Restore(tunnel.ID); err == nil {
		t.Fatal("restore without a last-known-good must fail")
	}

	if err := store.Write(ctx, tunnel, proxy("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, tunnel, proxy("5.6.7.8")); err != nil {
		t.Fatal(err)
	}

	restored, err := store.Restore(tunnel.ID)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if restored.Server != "1.2.3.4" {
		t.Fatalf("expected the previous upstream back, got %+v", restored)
	}
	current, _, hasPrevious := store.Current(tunnel.ID)
	if current.Server != "1.2.3.4" || !hasPrevious {
		t.Fatalf("unexpected state after restore: %+v %v", current, hasPrevious)
	}

	// Restoring again returns to where we started: the swap kept both.
	again, err := store.Restore(tunnel.ID)
	if err != nil {
		t.Fatalf("second Restore: %v", err)
	}
	if again.Server != "5.6.7.8" {
		t.Fatalf("expected the demoted upstream back, got %+v", again)
	}
}

func TestRotateKeepsThePreviousKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "server.key")
	store := ServerKeyFile{Path: path}

	if _, err := store.Rotate(); err == nil {
		t.Fatal("rotating a missing key must fail")
	}

	firstPublic, err := store.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	firstPrivate, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	secondPublic, err := store.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if secondPublic == firstPublic {
		t.Fatal("rotation produced the same key")
	}

	previous, err := os.ReadFile(path + ".previous")
	if err != nil {
		t.Fatalf("the previous key was not kept: %v", err)
	}
	if strings.TrimSpace(string(previous)) != strings.TrimSpace(string(firstPrivate)) {
		t.Fatal("the kept key is not the old one")
	}

	// The new key on disk matches the returned public half.
	livePrivate, err := store.PrivateKey(context.Background())
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	livePublic, err := domain.PublicKeyFromPrivate(livePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if livePublic != secondPublic {
		t.Fatal("the stored key does not match the announced public key")
	}
}
