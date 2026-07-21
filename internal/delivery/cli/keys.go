package cli

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
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
	var egress, address, output string
	command := &cobra.Command{
		Use:   "add <device>",
		Short: "Generate a device key pair, print its entry and write its client profile",
		Long: "The private key exists only here: it goes straight into the client profile " +
			"and is never stored by the hub, which needs only the public half. Re-issuing " +
			"a lost profile therefore means generating a new key, which is the right " +
			"answer anyway.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			if egress == "" {
				return fmt.Errorf("--egress is required (a tunnel ID, or %q)", domain.EgressDirect)
			}
			if err := validateHostAddress(address); err != nil {
				return err
			}

			service := newService(*configPath, "")
			cfg, err := service.LoadAndValidate(cmd.Context())
			if err != nil {
				return err
			}

			privateKey, publicKey, err := domain.GenerateX25519KeyPair()
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), `# Append to the devices list in %s:
  - id: %s
    address: %q
    public_key: %q
    egress: %s
`, *configPath, deviceID, address, publicKey, egress)
			if err != nil {
				return err
			}

			if output == "" {
				return nil
			}
			profile, err := runtimeadapter.AmneziaProfileRenderer{}.Render(cfg.Hub, address, privateKey)
			if err != nil {
				return err
			}
			// os.WriteFile applies the 0600 mode only when it creates the file; an
			// existing target keeps its old, possibly world-readable, permissions.
			// The profile carries the device private key, so open explicitly and
			// chmod to guarantee 0600 whether or not the file already existed.
			out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("write profile: %w", err)
			}
			if err := out.Chmod(0o600); err != nil {
				_ = out.Close()
				return fmt.Errorf("secure profile permissions: %w", err)
			}
			if _, err := out.WriteString(profile); err != nil {
				_ = out.Close()
				return fmt.Errorf("write profile: %w", err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("write profile: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "\nwrote client profile to %s\n", output)
			return err
		},
	}
	command.Flags().StringVar(&egress, "egress", "", "tunnel carrying this device's internet traffic, or direct")
	command.Flags().StringVar(&address, "address", "", "host address inside hub.client_cidr, for example 10.80.0.2/32")
	command.Flags().StringVar(&output, "output", "", "where to write the client profile; omit to print only the entry")
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
