package main

import (
	"context"
	"fmt"
	"os"

	"vpn-hub/internal/delivery/cli"
)

func main() {
	if err := cli.NewHubctlCommand(os.Stdout, os.Stderr).ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "hubctl:", err)
		os.Exit(1)
	}
}
