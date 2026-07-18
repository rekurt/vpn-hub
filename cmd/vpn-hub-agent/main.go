package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"vpn-hub/internal/delivery/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.NewAgentCommand(os.Stdout, os.Stderr).ExecuteContext(ctx); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "vpn-hub-agent:", err)
		os.Exit(1)
	}
}
