package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"vpn-hub/internal/adapters/linux"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/delivery/bot"
)

func NewBotCommand(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "vpn-hub-bot",
		Short:         "Telegram bot: manage the hub from a chat",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.AddCommand(newBotServeCommand())
	root.AddCommand(newBotCheckCommand())
	return root
}

// botFlags mirror the agent's path conventions; the bot needs all of them because
// it is both an operator seat (config, state) and an observer (journal, runtime).
type botFlags struct {
	telegramConfig string
	configPath     string
	stateDir       string
	configDir      string
	runtimeDir     string
	keyPath        string
}

func (f *botFlags) bind(command *cobra.Command) {
	command.Flags().StringVar(&f.telegramConfig, "telegram-config", "/etc/vpn-hub/telegram.yaml", "bot token and admin id")
	command.Flags().StringVarP(&f.configPath, "config", "c", "/etc/vpn-hub/hub.yaml", "path to the hub YAML configuration")
	command.Flags().StringVar(&f.stateDir, "state-dir", "/var/lib/vpn-hub", "agent state directory")
	command.Flags().StringVar(&f.configDir, "config-dir", "/etc/vpn-hub", "directory holding upstream tunnel configurations")
	command.Flags().StringVar(&f.runtimeDir, "runtime-dir", linux.DefaultRuntimeDir, "tmpfs directory for material that must not reach disk")
	command.Flags().StringVar(&f.keyPath, "server-key", "/etc/vpn-hub/server.key", "path to the hub private key")
}

func newBotServeCommand() *cobra.Command {
	flags := &botFlags{}
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the bot until stopped",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := bot.LoadConfig(cmd.Context(), flags.telegramConfig)
			if err != nil {
				return err
			}
			instance := bot.New(cfg, &tg.Client{Token: cfg.Token},
				flags.configPath, flags.stateDir, flags.configDir, flags.runtimeDir, flags.keyPath,
				cmd.ErrOrStderr())
			return instance.Run(cmd.Context())
		},
	}
	flags.bind(command)
	return command
}

// newBotCheckCommand is the setup helper: it proves the token works without
// starting anything, and echoes whose commands the bot would obey.
func newBotCheckCommand() *cobra.Command {
	flags := &botFlags{}
	command := &cobra.Command{
		Use:   "check",
		Short: "Validate the bot configuration and token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := bot.LoadConfig(cmd.Context(), flags.telegramConfig)
			if err != nil {
				return err
			}
			me, err := (tg.Client{Token: cfg.Token}).GetMe(cmd.Context())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "token is valid: bot @%s; obeying admin id %d\n", me.Username, cfg.AdminID)
			return err
		},
	}
	flags.bind(command)
	return command
}
