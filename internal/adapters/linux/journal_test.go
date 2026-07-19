package linux

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestTailAsksForTheUnit(t *testing.T) {
	t.Parallel()
	var recorded []string
	journal := Journal{Run: func(_ context.Context, name string, args ...string) (string, error) {
		recorded = append(recorded, name+" "+strings.Join(args, " "))
		return "line", nil
	}}

	output, err := journal.Tail(context.Background(), "vpn-hub-agent.service", 50)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if output != "line" {
		t.Fatalf("unexpected output %q", output)
	}
	expected := "journalctl -u vpn-hub-agent.service -n 50 --no-pager -o short-iso"
	if len(recorded) != 1 || recorded[0] != expected {
		t.Fatalf("expected %q, ran %v", expected, recorded)
	}
}

func TestFollowDecodesEntries(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := `{"MESSAGE":"converged on revision abc123","_SYSTEMD_UNIT":"vpn-hub-agent.service","__REALTIME_TIMESTAMP":"1700000000000000"}
not json at all
{"MESSAGE":[104,105],"_SYSTEMD_UNIT":"vpn-hub-agent.service","__REALTIME_TIMESTAMP":"1700000001000000"}
`
	journal := Journal{Start: func(context.Context, []string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(stream)), nil
	}}

	entries := journal.Follow(ctx, []string{"vpn-hub-agent.service"})

	first := <-entries
	if first.Message != "converged on revision abc123" {
		t.Fatalf("unexpected message %q", first.Message)
	}
	if first.Unit != "vpn-hub-agent.service" {
		t.Fatalf("unexpected unit %q", first.Unit)
	}
	if first.At != time.UnixMicro(1700000000000000) {
		t.Fatalf("unexpected time %v", first.At)
	}

	// The byte-array encoding journald uses for non-UTF-8 payloads still decodes.
	second := <-entries
	if second.Message != "hi" {
		t.Fatalf("unexpected message %q", second.Message)
	}

	cancel()
	// The channel closes once the context ends, so a consumer's range loop ends too.
	for range entries { //nolint:revive // draining until close is the point
	}
}
