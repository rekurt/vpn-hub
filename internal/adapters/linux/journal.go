package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"strconv"
	"time"
)

// JournalEntry is one line the journal recorded for a unit.
type JournalEntry struct {
	Unit    string
	Message string
	At      time.Time
}

// Journal reads systemd's journal. Tail answers "what happened lately"; Follow is a
// live stream, which is the only way the bot learns about agent events -- the agent
// reports to its journal and nowhere else, by design.
type Journal struct {
	Run runner
	// Start launches the follow subprocess and returns its output stream. Tests
	// substitute a reader; the default runs journalctl.
	Start func(ctx context.Context, units []string) (io.ReadCloser, error)
}

func (j Journal) run(ctx context.Context, name string, args ...string) (string, error) {
	if j.Run != nil {
		return j.Run(ctx, name, args...)
	}
	return execRunner(ctx, name, args...)
}

// Tail returns the last lines for one unit, newest last.
func (j Journal) Tail(ctx context.Context, unit string, lines int) (string, error) {
	return j.run(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(lines),
		"--no-pager", "-o", "short-iso")
}

// Follow streams new entries for the given units until the context ends. The
// subprocess is restarted with backoff when it dies: losing the stream quietly would
// mean losing exactly the alerts it exists to deliver.
func (j Journal) Follow(ctx context.Context, units []string) <-chan JournalEntry {
	entries := make(chan JournalEntry, 64)
	go func() {
		defer close(entries)
		backoff := time.Second
		for ctx.Err() == nil {
			stream, err := j.start(ctx, units)
			if err == nil {
				decodeJournal(ctx, stream, entries)
				_ = stream.Close()
				backoff = time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()
	return entries
}

func (j Journal) start(ctx context.Context, units []string) (io.ReadCloser, error) {
	if j.Start != nil {
		return j.Start(ctx, units)
	}
	args := []string{"-f", "-n", "0", "-o", "json"}
	for _, unit := range units {
		args = append(args, "-u", unit)
	}
	command := exec.CommandContext(ctx, "journalctl", args...)
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return &reapingPipe{ReadCloser: pipe, wait: command.Wait}, nil
}

// reapingPipe waits for the subprocess on Close, so a dead journalctl does not stay
// a zombie until the bot exits.
type reapingPipe struct {
	io.ReadCloser
	wait func() error
}

func (p *reapingPipe) Close() error {
	err := p.ReadCloser.Close()
	_ = p.wait()
	return err
}

func decodeJournal(ctx context.Context, stream io.Reader, entries chan<- JournalEntry) {
	scanner := bufio.NewScanner(stream)
	// Journal lines carry whole stack traces when something crashes; the default
	// 64K token limit would end the stream exactly on the interesting entry.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		entry, ok := parseJournalLine(scanner.Bytes())
		if !ok {
			continue
		}
		select {
		case entries <- entry:
		case <-ctx.Done():
			return
		}
	}
}

func parseJournalLine(line []byte) (JournalEntry, bool) {
	var record struct {
		Message   json.RawMessage `json:"MESSAGE"`
		Unit      string          `json:"_SYSTEMD_UNIT"`
		Timestamp string          `json:"__REALTIME_TIMESTAMP"`
	}
	if err := json.Unmarshal(line, &record); err != nil {
		return JournalEntry{}, false
	}
	message, ok := journalMessage(record.Message)
	if !ok {
		return JournalEntry{}, false
	}
	entry := JournalEntry{Unit: record.Unit, Message: message}
	if micros, err := strconv.ParseInt(record.Timestamp, 10, 64); err == nil {
		entry.At = time.UnixMicro(micros)
	}
	return entry, true
}

// journalMessage handles both encodings journald uses: a string, or an array of
// bytes when the payload is not valid UTF-8.
func journalMessage(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, true
	}
	var bytes []byte
	if err := json.Unmarshal(raw, &bytes); err == nil {
		return string(bytes), true
	}
	return "", false
}
