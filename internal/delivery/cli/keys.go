package cli

import (
	"fmt"
	"net/netip"

	"github.com/spf13/cobra"

	"vpn-hub/internal/adapters/linux"
	"vpn-hub/internal/domain"
)

func newKeygenCommand() *cobra.Command {
	var output string
	command := &cobra.Command{
		Use:   "keygen",
		Short: "Generate the hub key pair and print the public half",
		Long: "Writes the private key to --output with mode 0600 and prints the public key " +
			"to paste into hub.server_public_key. Refuses to overwrite an existing key, " +
			"because replacing it invalidates every client profile already issued.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			publicKey, err := linux.ServerKeyFile{Path: output}.Create()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"wrote %s\nserver_public_key: %q\n", output, publicKey)
			return err
		},
	}
	command.Flags().StringVar(&output, "output", "/etc/vpn-hub/server.key", "where to write the hub private key")
	return command
}

func newDeviceAddCommand(configPath *string) *cobra.Command {
	var deviceID, egress, address string
	command := &cobra.Command{
		Use:   "add <device>",
		Short: "Print a device profile block with a fresh key pair",
		Long: "Generates a key pair and prints the YAML to paste into devices. The private " +
			"key is shown once and never stored by the hub, which only ever needs the " +
			"public half.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID = args[0]
			if egress == "" {
				return fmt.Errorf("--egress is required (a tunnel ID, or %q)", domain.EgressDirect)
			}
			if err := validateHostAddress(address); err != nil {
				return err
			}

			privateKey, publicKey, err := domain.GenerateX25519KeyPair()
			if err != nil {
				return err
			}
			profileID := deviceID + "-" + egress

			_, err = fmt.Fprintf(cmd.OutOrStdout(), `# Append to the devices list in %s.
# The hub stores only client_public_key; keep client_private_key with the device.
  - id: %s
    profiles:
      - id: %s
        egress: %s
        address: %q
        client_public_key: %q
        # client_private_key: %q
`, *configPath, deviceID, profileID, egress, address, publicKey, privateKey)
			return err
		},
	}
	command.Flags().StringVar(&egress, "egress", "", "egress tunnel ID, or direct")
	command.Flags().StringVar(&address, "address", "", "host address inside hub.client_cidr, for example 10.80.0.2/32")
	return command
}

func validateHostAddress(value string) error {
	if value == "" {
		return fmt.Errorf("--address is required, for example 10.80.0.2/32")
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("invalid --address %q: it must be a host route such as 10.80.0.2/32", value)
	}
	bits := 32
	if prefix.Addr().Is6() {
		bits = 128
	}
	if prefix.Bits() != bits {
		return fmt.Errorf("--address %q must be a host route, so /%d", value, bits)
	}
	return nil
}
