package cli

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/domain"
)

func newClientACLCommand(configPath *string) *cobra.Command {
	command := newParentCommand("client-acl", "Manage client-to-client port access")
	command.AddCommand(
		newClientACLListCommand(configPath),
		newClientACLAddCommand(configPath),
		newClientACLRemoveCommand(configPath),
	)
	return command
}

func newClientACLListCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List client-to-client port ACLs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := newService(*configPath, "").LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "SOURCE\tTARGET\tPORT")
			for _, rule := range cfg.ClientACLs {
				_, _ = fmt.Fprintf(writer, "%s\t%s\t%s/%d\n", rule.Source, rule.Target, rule.Protocol, rule.Port)
			}
			return writer.Flush()
		},
	}
}

func newClientACLAddCommand(configPath *string) *cobra.Command {
	return clientACLMutationCommand(configPath, "add", "Allow one client-to-client port", true)
}

func newClientACLRemoveCommand(configPath *string) *cobra.Command {
	return clientACLMutationCommand(configPath, "remove", "Remove one client-to-client port ACL", false)
}

func clientACLMutationCommand(configPath *string, use, short string, add bool) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <source|any> <target> <tcp|udp>/<port>",
		Short: short,
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			protocol, port, err := parseClientACLSpec(args[2])
			if err != nil {
				return err
			}
			editor := configadapter.Editor{Root: *configPath}
			if add {
				err = editor.AddClientACL(args[0], args[1], string(protocol), port)
			} else {
				err = editor.RemoveClientACL(args[0], args[1], string(protocol), port)
			}
			if err != nil {
				return err
			}
			if _, err := newService(*configPath, "").LoadAndValidate(cmd.Context()); err != nil {
				if add {
					if revertErr := editor.RemoveClientACL(args[0], args[1], string(protocol), port); revertErr != nil {
						return fmt.Errorf("change left the config invalid (%w) AND the revert failed (%w); fix %s by hand", err, revertErr, *configPath)
					}
				} else {
					if revertErr := editor.AddClientACL(args[0], args[1], string(protocol), port); revertErr != nil {
						return fmt.Errorf("change left the config invalid (%w) AND the revert failed (%w); fix %s by hand", err, revertErr, *configPath)
					}
				}
				return fmt.Errorf("reverted: %w", err)
			}
			verb := "allowed"
			if !add {
				verb = "removed"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s -> %s %s/%d; run `hubctl deploy` to apply\n", verb, args[0], args[1], protocol, port)
			return err
		},
	}
}

func parseClientACLSpec(value string) (domain.ClientACLProtocol, uint16, error) {
	protocol, rawPort, ok := strings.Cut(strings.ToLower(strings.TrimSpace(value)), "/")
	if !ok || rawPort == "" {
		return "", 0, fmt.Errorf("port ACL must look like tcp/22 or udp/53")
	}
	if protocol != string(domain.ClientACLTCP) && protocol != string(domain.ClientACLUDP) {
		return "", 0, fmt.Errorf("unsupported protocol %q", protocol)
	}
	port64, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port64 == 0 {
		return "", 0, fmt.Errorf("invalid port %q", rawPort)
	}
	return domain.ClientACLProtocol(protocol), uint16(port64), nil
}
