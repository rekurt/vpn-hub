package cli

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/domain"
)

func newTunnelCommand(configPath *string) *cobra.Command {
	command := newParentCommand("tunnel", "Inspect and change tunnels")
	command.AddCommand(
		newTunnelListCommand(configPath),
		newTunnelToggleCommand(configPath, true),
		newTunnelToggleCommand(configPath, false),
		newTunnelListEditCommand(configPath, "routes", "subnet reachable through this tunnel"),
		newTunnelListEditCommand(configPath, "zones", "private domain resolved through this tunnel"),
	)
	return command
}

func newTunnelListCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List tunnels and whether they are enabled",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := newService(*configPath, "").LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "ID\tROLE\tTYPE\tENABLED\tROUTES\tZONES")
			for _, tunnel := range cfg.Tunnels {
				_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%t\t%s\t%s\n",
					tunnel.ID, tunnel.Role, tunnel.Type, tunnel.IsEnabled(),
					summarise(tunnel.Routes), summarise(tunnel.DNSZones))
			}
			return writer.Flush()
		},
	}
}

func newTunnelToggleCommand(configPath *string, enable bool) *cobra.Command {
	verb := "disable"
	if enable {
		verb = "enable"
	}
	return &cobra.Command{
		Use:   verb + " <id>",
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " a tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			editor := configadapter.Editor{Root: *configPath}
			if err := editor.SetTunnelField(args[0], "enabled", fmt.Sprint(enable)); err != nil {
				return err
			}
			// Validate after writing so the operator is told immediately when the
			// change leaves a device without a way out -- and can undo it knowingly
			// rather than discovering it at the next deploy.
			if _, err := newService(*configPath, "").LoadAndValidate(cmd.Context()); err != nil {
				_ = editor.SetTunnelField(args[0], "enabled", fmt.Sprint(!enable))
				return fmt.Errorf("reverted: %w", err)
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%sd %s; run `hubctl deploy` to apply\n", verb, args[0])
			return err
		},
	}
}

func newTunnelListEditCommand(configPath *string, name, what string) *cobra.Command {
	field := map[string]string{"routes": "routes", "zones": "dns_zones"}[name]
	var add, remove string
	command := &cobra.Command{
		Use:   name + " <tunnel>",
		Short: "Add or remove a " + what,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (add == "") == (remove == "") {
				return fmt.Errorf("give exactly one of --add or --remove")
			}
			editor := configadapter.Editor{Root: *configPath}
			var err error
			if add != "" {
				err = editor.AppendListItem(args[0], field, add)
			} else {
				err = editor.RemoveListItem(args[0], field, remove)
			}
			if err != nil {
				return err
			}
			if _, err := newService(*configPath, "").LoadAndValidate(cmd.Context()); err != nil {
				return fmt.Errorf("the change was written but does not validate, so it will not deploy: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "updated %s of %s; run `hubctl deploy` to apply\n", field, args[0])
			return err
		},
	}
	command.Flags().StringVar(&add, "add", "", "value to add")
	command.Flags().StringVar(&remove, "remove", "", "value to remove")
	return command
}

func newDeviceListCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List devices and their default internet path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := newService(*configPath, "").LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "ID\tADDRESS\tEGRESS")
			for _, device := range cfg.Devices {
				_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\n", device.ID, device.Address, device.Egress)
			}
			return writer.Flush()
		},
	}
}

func newDeviceSetEgressCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "set-egress <device> <tunnel>",
		Short: "Change which tunnel carries a device's internet traffic",
		Long: "The device keeps one connection and one profile; the choice lives on the " +
			"hub, so nothing has to change on the client.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := newService(*configPath, "").LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			previous := ""
			for _, device := range cfg.Devices {
				if device.ID == args[0] {
					previous = device.Egress
				}
			}

			editor := configadapter.Editor{Root: *configPath}
			if err := editor.SetDeviceField(args[0], "egress", args[1]); err != nil {
				return err
			}
			if _, err := newService(*configPath, "").LoadAndValidate(cmd.Context()); err != nil {
				if previous != "" {
					_ = editor.SetDeviceField(args[0], "egress", previous)
				}
				return fmt.Errorf("reverted: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"%s now leaves through %s; run `hubctl deploy` to apply\n", args[0], args[1])
			return err
		},
	}
}

// newRoutesCommand answers "why does this address go there", which is otherwise only
// answerable by reading the ruleset by eye.
func newRoutesCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "routes",
		Short: "Show which destinations the hub sends through which tunnel",
		Args:  cobra.NoArgs,
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

			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "DESTINATION\tVIA\tWHY")
			for _, tunnel := range state.Tunnels {
				if tunnel.Role != domain.RolePrivateNetwork {
					continue
				}
				for _, route := range tunnel.Routes {
					_, _ = fmt.Fprintf(writer, "%s\t%s\tprivate network\n", route, tunnel.ID)
				}
				for _, zone := range tunnel.DNSZones {
					_, _ = fmt.Fprintf(writer, "*.%s\t%s\tprivate domain\n", zone, tunnel.ID)
				}
			}

			byEgress := map[string][]string{}
			for _, device := range state.Devices {
				byEgress[device.Egress] = append(byEgress[device.Egress], device.ID)
			}
			for _, egress := range sortedKeys(byEgress) {
				devices := byEgress[egress]
				sort.Strings(devices)
				_, _ = fmt.Fprintf(writer, "everything else\t%s\tdefault for %s\n", egress, strings.Join(devices, ", "))
			}
			return writer.Flush()
		},
	}
}

func summarise(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	if len(values) <= 2 {
		return strings.Join(values, ",")
	}
	return fmt.Sprintf("%s,+%d", values[0], len(values)-1)
}

func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
