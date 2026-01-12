package cmd

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "zapret-daemon",
	Short: "Zapret daemon service",
	Long: `Zapret daemon is a background service that manages zapret operations.
It provides a control interface via Unix socket or network connection.`,
	SilenceUsage: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: /etc/zapret-ng/config.yaml)")
}

// GetConfigPath returns the config file path.
func GetConfigPath() string {
	if cfgFile == "" {
		return "/etc/zapret-ng/config.yaml"
	}
	return cfgFile
}
