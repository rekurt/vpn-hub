package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"vpn-hub/internal/adapters/health"
	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
	"vpn-hub/internal/wiring"
)

func NewHubctlCommand(out, errOut io.Writer) *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "hubctl",
		Short:         "Manage a private multi-VPN hub",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "configs/hub.yaml", "path to the hub YAML configuration")

	root.AddCommand(newValidateCommand(&configPath))
	root.AddCommand(newDeployCommand(&configPath))
	root.AddCommand(newStatusCommand())
	root.AddCommand(newTestCommand(&configPath))
	root.AddCommand(newSubscriptionCommand(&configPath))
	root.AddCommand(newDeviceCommand(&configPath))
	root.AddCommand(newTunnelCommand(&configPath))
	root.AddCommand(newRoutesCommand(&configPath))
	root.AddCommand(newConfirmCommand())
	root.AddCommand(newRollbackCommand())
	root.AddCommand(newKeygenCommand())
	return root
}

// newParentCommand builds a command that only groups subcommands. Cobra skips argument
// validation for commands without a Run, so an unknown positional would otherwise be
// silently swallowed; making the parent runnable lets NoArgs reject it.
func newParentCommand(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
}

func newValidateCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and build a redacted desired state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			service := newService(*configPath, "")
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			state, err := service.BuildDesiredState(cfg)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "valid: revision=%s tunnels=%d devices=%d\n", state.Revision, len(state.Tunnels), len(state.Devices))
			return err
		},
	}
}

func newDeployCommand(configPath *string) *cobra.Command {
	var stateDir string
	var dryRun bool
	var confirmWithin time.Duration
	command := &cobra.Command{
		Use:   "deploy",
		Short: "Compile and safely apply a desired-state revision locally",
		RunE: func(cmd *cobra.Command, _ []string) error {
			service := newService(*configPath, stateDir)
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			// Applied after validation and before compiling the revision, so a revoked
			// device never reaches the state the agent converges on.
			revoked, err := runtimeadapter.RevocationStore{StateDir: stateDir}.Load(cmd.Context())
			if err != nil {
				return err
			}
			if len(revoked) > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "excluding %d revoked device(s): %s\n", len(revoked), strings.Join(revoked, ", "))
			}
			state, err := service.BuildDesiredState(application.RemoveRevoked(cfg, revoked))
			if err != nil {
				return err
			}
			if dryRun {
				_, err = fmt.Fprintf(cmd.OutOrStdout(),
					"dry-run: revision %s compiles (%d tunnels, %d devices); nothing was written\n",
					state.Revision, len(state.Tunnels), len(state.Devices))
				return err
			}
			confirmations := runtimeadapter.ConfirmationStore{StateDir: stateDir}
			var armed bool
			if confirmWithin > 0 {
				if armed, err = confirmations.Arm(cmd.Context(), confirmWithin, state.Revision); err != nil {
					return err
				}
			}
			if err := service.Save(cmd.Context(), state); err != nil {
				return err
			}
			if confirmWithin > 0 {
				if !armed {
					// Said plainly rather than implied: an operator who reads the
					// usual message trusts a rollback that is not there.
					_, err = fmt.Fprintf(cmd.OutOrStdout(),
						"saved revision %s; no rollback was armed because there is no earlier revision to return to\n",
						state.Revision)
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(),
					"saved revision %s; run `hubctl confirm` within %s or the agent restores the previous one\n",
					state.Revision, confirmWithin)
				return err
			}
			// The agent converges the host onto this; hubctl never touches it.
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"saved revision %s to %s; the agent applies it on its next pass\n", state.Revision, stateDir)
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	// Defaulting this to true made `deploy` a command that reported success and did
	// nothing -- including `deploy --confirm-within 5m`, which armed no timer, so an
	// operator believed a remote hub was covered by an automatic rollback that did
	// not exist. A verb does what it says; asking for a rehearsal is the thing that
	// takes a flag.
	command.Flags().BoolVar(&dryRun, "dry-run", false, "print the plan without persisting state")
	command.Flags().DurationVar(&confirmWithin, "confirm-within", 0,
		"restore the previous revision unless `hubctl confirm` runs within this time")
	return command
}

func newConfirmCommand() *cobra.Command {
	var stateDir string
	command := &cobra.Command{
		Use:   "confirm",
		Short: "Accept the deployed revision and drop the rollback timer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := runtimeadapter.ConfirmationStore{StateDir: stateDir}
			pending, armed, err := store.Load()
			if err != nil {
				return err
			}
			if !armed {
				return fmt.Errorf("nothing is awaiting confirmation")
			}
			if err := store.Confirm(); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "confirmed revision %s\n", pending.Revision)
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	return command
}

func newRollbackCommand() *cobra.Command {
	var stateDir string
	command := &cobra.Command{
		Use:   "rollback",
		Short: "Return to the previous revision now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := runtimeadapter.ConfirmationStore{StateDir: stateDir}.Rollback(cmd.Context())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"restored revision %s; the agent applies it on its next pass\n", state.Revision)
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	return command
}

func newStatusCommand() *cobra.Command {
	var stateDir string
	command := &cobra.Command{
		Use:   "status",
		Short: "Show the active desired-state revision",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := runtimeadapter.FileRevisionStore{StateDir: stateDir}.Load(cmd.Context())
			if err != nil {
				return err
			}
			// This is the revision the hub was told to converge on, read back from
			// disk. It is not a report of what the machine is currently doing;
			// observing that arrives with the reconciler.
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "desired: revision=%s generated_at=%s tunnels=%d devices=%d\n", state.Revision, state.GeneratedAt.Format("2006-01-02T15:04:05Z"), len(state.Tunnels), len(state.Devices)); err != nil {
				return err
			}
			pending, armed, err := runtimeadapter.ConfirmationStore{StateDir: stateDir}.Load()
			if err != nil || !armed {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"awaiting confirmation: %s left before the previous revision is restored\n",
				time.Until(pending.Deadline).Round(time.Second))
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	return command
}

func newTestCommand(configPath *string) *cobra.Command {
	command := newParentCommand("test", "Run preflight probes")
	tunnel := &cobra.Command{
		Use:   "tunnel <id>",
		Short: "Run configured preflight probes for one tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tunnelID := args[0]
			service := newService(*configPath, "")
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			healthState, err := service.TestTunnel(cmd.Context(), cfg, tunnelID)
			if err != nil {
				return err
			}
			switch healthState.Status {
			case domain.HealthHealthy:
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "healthy: tunnel=%s checked_at=%s\n",
					tunnelID, healthState.CheckedAt.Format("2006-01-02T15:04:05Z"))
				return err
			case domain.HealthUnhealthy:
				return fmt.Errorf("tunnel %s is unhealthy: %s", tunnelID, healthState.Reason)
			default:
				// Deliberately an error: a script must not read "could not tell" as "fine".
				return fmt.Errorf("tunnel %s health is unknown: %s", tunnelID, healthState.Reason)
			}
		},
	}
	command.AddCommand(tunnel)
	return command
}

func newSubscriptionCommand(configPath *string) *cobra.Command {
	var configDir string
	command := newParentCommand("subscription", "Manage provider subscriptions")
	refresh := &cobra.Command{
		Use:   "refresh <id>",
		Short: "Fetch a subscription, prove a candidate, and promote it",
		Long: "The candidate is brought up in an isolated namespace and has to carry " +
			"traffic before anything depends on it. A subscription that offers nothing " +
			"working leaves the active upstream exactly as it was.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := newService(*configPath, "").LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			var subject domain.Tunnel
			for _, tunnel := range cfg.Tunnels {
				if tunnel.ID == args[0] {
					subject = tunnel
				}
			}
			if subject.ID == "" {
				return fmt.Errorf("tunnel %q was not found", args[0])
			}

			uplink, err := linux.NetConf{}.UplinkInterface(cmd.Context())
			if err != nil {
				return err
			}
			canary := linux.Canary{Egress: linux.Egress{SecretsDir: "/run/vpn-hub"}}

			chosen, rejected, err := application.SubscriptionRefresher{
				Fetch: health.HTTPSSubscriptionFetcher{},
				Parse: linux.ParseSubscription,
				Prove: func(ctx context.Context, list []domain.ProxyTunnel) (domain.ProxyTunnel, []string, error) {
					return canary.SelectCandidate(ctx, list, uplink, nil)
				},
				Store: linux.UpstreamFile{Dir: configDir},
			}.Refresh(cmd.Context(), subject)

			for _, reason := range rejected {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "rejected %s\n", reason)
			}
			if err != nil {
				return err
			}
			// No deploy needed: the revision names the link file, not its contents,
			// so the agent re-reads it and restarts the proxy on its next pass.
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"promoted %s:%d for %s; the agent applies it on its next pass\n", chosen.Server, chosen.Port, subject.ID)
			return err
		},
	}
	refresh.Flags().StringVar(&configDir, "config-dir", "/etc/vpn-hub", "directory holding upstream configurations")

	var restoreConfigDir string
	restore := &cobra.Command{
		Use:   "restore <id>",
		Short: "Swap a subscription's upstream back to its last-known-good",
		Long: "The emergency counterpart to refresh, reachable over SSH when the bot is " +
			"not: when a subscription starts serving only broken nodes, this brings back " +
			"the previous working upstream. The swap is itself reversible.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			restored, err := linux.UpstreamFile{Dir: restoreConfigDir}.Restore(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"restored %s:%d for %s; the agent applies it on its next pass\n", restored.Server, restored.Port, args[0])
			return err
		},
	}
	restore.Flags().StringVar(&restoreConfigDir, "config-dir", "/etc/vpn-hub", "directory holding upstream configurations")

	command.AddCommand(refresh, restore)
	return command
}

func newDeviceCommand(configPath *string) *cobra.Command {
	var stateDir string
	command := newParentCommand("device", "Manage device admission")
	command.AddCommand(newDeviceAddCommand(configPath))
	command.AddCommand(newDeviceListCommand(configPath))
	command.AddCommand(newDeviceSetEgressCommand(configPath))
	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Persist a local device revocation consumed by the agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := (runtimeadapter.RevocationStore{StateDir: stateDir}).Add(cmd.Context(), args[0]); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"revoked device %s; run `hubctl deploy` to drop it from the active revision\n", args[0])
			return err
		},
	}
	revoke.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")

	var unrevokeStateDir string
	unrevoke := &cobra.Command{
		Use:   "unrevoke <id>",
		Short: "Lift a device revocation",
		Long: "Undoes an over-hasty `device revoke`. Without this, correcting a mistaken " +
			"revocation over SSH means editing the revocation file by hand; re-issuing the " +
			"device's profile from the bot also lifts it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := (runtimeadapter.RevocationStore{StateDir: unrevokeStateDir}).Remove(cmd.Context(), args[0]); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"lifted the revocation of %s; run `hubctl deploy` to restore it to the active revision\n", args[0])
			return err
		},
	}
	unrevoke.Flags().StringVar(&unrevokeStateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")

	command.AddCommand(revoke, unrevoke)
	return command
}

func newService(configPath, stateDir string) application.Service {
	return wiring.Service(configPath, stateDir)
}
