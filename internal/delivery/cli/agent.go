package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
)

func NewAgentCommand(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "vpn-hub-agent", Short: "Reconcile private multi-VPN hub desired state", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(errOut)
	root.AddCommand(newReconcileCommand())
	root.AddCommand(newServeCommand())
	root.AddCommand(newAgentStatusCommand())
	return root
}

// agentFlags are shared by every command that touches the host.
type agentFlags struct {
	stateDir   string
	keyPath    string
	runtimeDir string
}

func (f *agentFlags) bind(command *cobra.Command) {
	command.Flags().StringVar(&f.stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	command.Flags().StringVar(&f.keyPath, "server-key", "/etc/vpn-hub/server.key", "path to the hub private key")
	command.Flags().StringVar(&f.runtimeDir, "runtime-dir", "/run/vpn-hub", "tmpfs directory for material that must not reach disk")
}

// reconciler wires the host-facing adapters. Everything it drives only formats or
// executes; the decisions live in the application layer.
func (f *agentFlags) reconciler() ports.Reconciler {
	return application.HostReconciler{
		Firewall:  linux.NFTables{},
		Ingress:   linux.Ingress{SecretsDir: f.runtimeDir},
		Host:      linux.NetConf{},
		ServerKey: linux.ServerKeyFile{Path: f.keyPath},
	}
}

func newReconcileCommand() *cobra.Command {
	flags := &agentFlags{}
	var dryRun bool
	command := &cobra.Command{
		Use:   "reconcile",
		Short: "Reconcile the current desired state once",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return (&loop{flags: flags}).reconcile(cmd, dryRun)
		},
	}
	flags.bind(command)
	command.Flags().BoolVar(&dryRun, "dry-run", true, "print operations without touching the host")
	return command
}

func newServeCommand() *cobra.Command {
	flags := &agentFlags{}
	var interval time.Duration
	var once bool
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the desired-state reconciliation loop",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			run := &loop{flags: flags}
			if once {
				return run.reconcile(cmd, false)
			}
			if interval <= 0 {
				return fmt.Errorf("--interval must be greater than zero, got %s", interval)
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				if err := run.reconcile(cmd, false); err != nil {
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
	flags.bind(command)
	command.Flags().DurationVar(&interval, "interval", time.Minute, "reconciliation interval")
	command.Flags().BoolVar(&once, "once", false, "reconcile once and exit")
	return command
}

func newAgentStatusCommand() *cobra.Command {
	flags := &agentFlags{}
	command := &cobra.Command{
		Use:   "status",
		Short: "Show the revision the agent is converging on",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := runtimeadapter.FileRevisionStore{StateDir: flags.stateDir}.Load(cmd.Context())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "desired: revision=%s tunnels=%d devices=%d\n",
				state.Revision, len(state.Tunnels), len(state.Devices))
			return err
		},
	}
	flags.bind(command)
	return command
}

// loop carries what has to survive between ticks. It exists so the reconcile
// function has no package-level state: the suppression below is per-run, and a second
// agent in the same process would otherwise share it.
type loop struct {
	flags *agentFlags
	// applied is the last revision that converged. Reporting only on change keeps the
	// journal readable; an unconditional line per tick buries anything that matters.
	applied string
}

func (l *loop) reconcile(cmd *cobra.Command, dryRun bool) error {
	ctx := cmd.Context()
	state, err := runtimeadapter.FileRevisionStore{StateDir: l.flags.stateDir}.Load(ctx)
	if err != nil {
		return err
	}

	reconciler := l.flags.reconciler()
	if dryRun {
		operations, err := reconciler.Plan(ctx, state)
		if err != nil {
			return err
		}
		printOperations(cmd, operations)
		return nil
	}

	var operations []domain.Operation
	operations, err = reconciler.Apply(ctx, state)
	if err != nil {
		// Forget the revision so the next success reports again rather than staying
		// silent after an outage.
		l.applied = ""
		return err
	}
	// Report a difference whenever there was one, and otherwise stay quiet: an
	// unconditional line per tick buries the ticks that mattered.
	if len(operations) > 0 {
		printOperations(cmd, operations)
	}
	if l.applied != state.Revision {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "converged on revision %s\n", state.Revision)
		l.applied = state.Revision
	}
	return nil
}

func printOperations(cmd *cobra.Command, operations []domain.Operation) {
	for _, operation := range operations {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), operation)
	}
}
