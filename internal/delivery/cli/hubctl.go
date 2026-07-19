package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/adapters/health"
	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
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
	root.AddCommand(newProfileCommand(&configPath))
	root.AddCommand(newSubscriptionCommand(&configPath))
	root.AddCommand(newDeviceCommand(&configPath))
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
			if err := service.Save(cmd.Context(), state); err != nil {
				return err
			}
			// The agent converges the host onto this; hubctl never touches it.
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"saved revision %s to %s; the agent applies it on its next pass\n", state.Revision, stateDir)
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	command.Flags().BoolVar(&dryRun, "dry-run", true, "print the plan without persisting state")
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
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "desired: revision=%s generated_at=%s tunnels=%d devices=%d\n", state.Revision, state.GeneratedAt.Format("2006-01-02T15:04:05Z"), len(state.Tunnels), len(state.Devices))
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

func newProfileCommand(configPath *string) *cobra.Command {
	var deviceID, egress, output string
	command := newParentCommand("profile", "Manage client profiles")
	render := &cobra.Command{
		Use:   "render",
		Short: "Render one AmneziaWG client profile from local secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if deviceID == "" || egress == "" || output == "" {
				return fmt.Errorf("--device, --egress and --output are required")
			}
			service := newService(*configPath, "")
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			profile, err := service.RenderProfile(cfg, deviceID, egress)
			if err != nil {
				return err
			}
			if err := os.WriteFile(output, []byte(profile), 0o600); err != nil {
				return fmt.Errorf("write profile: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "written %s\n", output)
			return err
		},
	}
	render.Flags().StringVar(&deviceID, "device", "", "device ID")
	render.Flags().StringVar(&egress, "egress", "", "egress tunnel ID or direct")
	render.Flags().StringVar(&output, "output", "", "output profile path")
	command.AddCommand(render)
	return command
}

func newSubscriptionCommand(configPath *string) *cobra.Command {
	var output string
	command := newParentCommand("subscription", "Manage Xray subscriptions")
	refresh := &cobra.Command{
		Use:   "refresh <id>",
		Short: "Fetch and persist one Xray subscription candidate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				return fmt.Errorf("--output is required")
			}
			service := newService(*configPath, "")
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			payload, err := service.RefreshSubscription(cmd.Context(), cfg, args[0])
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(output, payload, 0o600); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "subscription candidate written to %s (%d bytes)\n", output, len(payload))
			return err
		},
	}
	refresh.Flags().StringVar(&output, "output", "", "candidate output path")
	command.AddCommand(refresh)
	return command
}

func newDeviceCommand(configPath *string) *cobra.Command {
	var stateDir string
	command := newParentCommand("device", "Manage device admission")
	command.AddCommand(newDeviceAddCommand(configPath))
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
	command.AddCommand(revoke)
	return command
}

func newService(configPath, stateDir string) application.Service {
	return application.Service{
		ConfigRepository: configadapter.ViperRepository{Path: configPath},
		RevisionStore:    runtimeadapter.FileRevisionStore{StateDir: stateDir},
		// Probing from the host would measure the host's own connectivity, which is
		// the path the tunnel exists to avoid.
		HealthChecker:       linux.HealthChecker{},
		SubscriptionFetcher: health.HTTPSSubscriptionFetcher{},
		ProfileRenderer:     runtimeadapter.AmneziaProfileRenderer{},
	}
}
