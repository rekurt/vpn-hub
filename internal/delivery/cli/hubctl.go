package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/adapters/health"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

func NewHubctlCommand(out, errOut *os.File) *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "hubctl",
		Short:         "Manage a private multi-VPN hub",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "config/hub.yaml", "path to the hub YAML configuration")

	root.AddCommand(newValidateCommand(&configPath))
	root.AddCommand(newDeployCommand(&configPath))
	root.AddCommand(newStatusCommand())
	root.AddCommand(newTestCommand(&configPath))
	root.AddCommand(newProfileCommand(&configPath))
	root.AddCommand(newSubscriptionCommand(&configPath))
	root.AddCommand(newDeviceCommand())
	return root
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
			state, err := service.BuildDesiredState(cfg)
			if err != nil {
				return err
			}
			operations, err := service.Deploy(cmd.Context(), state, !dryRun)
			if err != nil {
				return err
			}
			printOperations(cmd, operations)
			if dryRun {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "dry-run: no desired state was persisted")
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "applied desired-state revision %s to %s\n", state.Revision, stateDir)
			}
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
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "revision=%s generated_at=%s tunnels=%d devices=%d\n", state.Revision, state.GeneratedAt.Format("2006-01-02T15:04:05Z"), len(state.Tunnels), len(state.Devices))
			return err
		},
	}
	command.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	return command
}

func newTestCommand(configPath *string) *cobra.Command {
	var tunnelID string
	command := &cobra.Command{
		Use:   "test tunnel <id>",
		Short: "Run configured preflight probes for one tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tunnelID = args[0]
			service := newService(*configPath, "")
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			healthState, err := service.TestTunnel(cmd.Context(), cfg, tunnelID)
			if err != nil {
				return err
			}
			if !healthState.Healthy {
				return fmt.Errorf("tunnel %s is unhealthy: %s", tunnelID, healthState.Reason)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "healthy: tunnel=%s checked_at=%s\n", tunnelID, healthState.CheckedAt.Format("2006-01-02T15:04:05Z"))
			return err
		},
	}
	return command
}

func newProfileCommand(configPath *string) *cobra.Command {
	var deviceID, egress, output string
	command := &cobra.Command{
		Use:   "profile render",
		Short: "Render one AmneziaWG client profile from local secrets",
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
	command.Flags().StringVar(&deviceID, "device", "", "device ID")
	command.Flags().StringVar(&egress, "egress", "", "egress tunnel ID or direct")
	command.Flags().StringVar(&output, "output", "", "output profile path")
	return command
}

func newSubscriptionCommand(configPath *string) *cobra.Command {
	var output string
	command := &cobra.Command{Use: "subscription", Short: "Manage Xray subscriptions"}
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

func newDeviceCommand() *cobra.Command {
	var stateDir string
	command := &cobra.Command{Use: "device", Short: "Manage device admission"}
	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Persist a local device revocation consumed by the agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				return err
			}
			path := filepath.Join(stateDir, "revoked-devices.json")
			revoked := make(map[string]struct{})
			if data, err := os.ReadFile(path); err == nil {
				var values []string
				if err := json.Unmarshal(data, &values); err != nil {
					return fmt.Errorf("read revocations: %w", err)
				}
				for _, value := range values {
					revoked[value] = struct{}{}
				}
			} else if !os.IsNotExist(err) {
				return err
			}
			revoked[args[0]] = struct{}{}
			values := make([]string, 0, len(revoked))
			for value := range revoked {
				values = append(values, value)
			}
			sort.Strings(values)
			data, _ := json.MarshalIndent(values, "", "  ")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "revoked device %s\n", args[0])
			return err
		},
	}
	revoke.Flags().StringVar(&stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	command.AddCommand(revoke)
	return command
}

func newService(configPath, stateDir string) application.Service {
	reconciler := runtimeadapter.FileReconciler{StateDir: stateDir}
	return application.Service{
		ConfigRepository:    configadapter.ViperRepository{Path: configPath},
		RevisionStore:       runtimeadapter.FileRevisionStore{StateDir: stateDir},
		Reconciler:          reconciler,
		HealthChecker:       health.ProbeChecker{},
		SubscriptionFetcher: health.HTTPSSubscriptionFetcher{},
		ProfileRenderer:     runtimeadapter.AmneziaProfileRenderer{},
	}
}

func printOperations(cmd *cobra.Command, operations []domain.Operation) {
	for _, operation := range operations {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %-28s %s\n", strings.ToUpper(operation.Kind), operation.Resource, operation.Description)
	}
}
