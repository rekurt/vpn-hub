package linux

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// QREncoder renders text as a PNG QR code via the qrencode binary, which cloud-init
// installs on the hub.
type QREncoder struct {
	// Exec runs the encoder; tests substitute a fake. The text travels on stdin, not
	// argv: a client profile carries a private key, and argv is visible to every
	// process on the host for as long as the command runs.
	Exec func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)
}

// PNG encodes text into a QR code image.
func (q QREncoder) PNG(ctx context.Context, text string) ([]byte, error) {
	run := q.Exec
	if run == nil {
		run = execStdin
	}
	return run(ctx, text, "qrencode", "-t", "PNG", "-o", "-")
}

// execStdin is execRunner's sibling for commands that read stdin and answer with
// binary output.
func execStdin(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
		}
		return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return stdout.Bytes(), nil
}
