package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
)

func NewAgentCommand(out, errOut *os.File) *cobra.Command {
	root := &cobra.Command{Use: "vpn-hub-agent", Short: "Reconcile private multi-VPN hub desired state", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(errOut)
	root.AddCommand(newReconcileCommand())
	root.AddCommand(newServeCommand())
	root.AddCommand(newAgentStatusCommand())
	return root
}

func newReconcileCommand() *cobra.Command {
	var stateDir string
	var dryRun bool
	command := &cobra.Command{
		Use:   "reconcile",
		Short: "Reconcile the current desired state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return reconcile(cmd, stateDir, dryRun)
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	command.Flags().BoolVar(&dryRun, "dry-run", true, "print operations without persisting state")
	return command
}

func newServeCommand() *cobra.Command {
	var stateDir string
	var interval time.Duration
	var once bool
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the desired-state reconciliation loop",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if once {
				return reconcile(cmd, stateDir, false)
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				if err := reconcile(cmd, stateDir, false); err != nil {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), err)
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-ticker.C:
				}
			}
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	command.Flags().DurationVar(&interval, "interval", time.Minute, "reconciliation interval")
	command.Flags().BoolVar(&once, "once", false, "reconcile once and exit")
	return command
}

func newAgentStatusCommand() *cobra.Command {
	var stateDir string
	command := &cobra.Command{
		Use:   "status",
		Short: "Show agent desired state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := runtimeadapter.FileRevisionStore{StateDir: stateDir}.Load(cmd.Context())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "revision=%s tunnels=%d devices=%d\n", state.Revision, len(state.Tunnels), len(state.Devices))
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	return command
}

func reconcile(cmd *cobra.Command, stateDir string, dryRun bool) error {
	store := runtimeadapter.FileRevisionStore{StateDir: stateDir}
	state, err := store.Load(cmd.Context())
	if err != nil {
		return err
	}
	reconciler := runtimeadapter.FileReconciler{StateDir: stateDir}
	operations, err := reconciler.Plan(cmd.Context(), state)
	if err != nil {
		return err
	}
	printOperations(cmd, operations)
	if dryRun {
		return nil
	}
	return reconciler.Apply(cmd.Context(), state)
}
