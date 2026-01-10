package cmd

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/Sergeydigl3/zapret-nix/internal/config"
	"github.com/Sergeydigl3/zapret-nix/rpc/daemon"
)

var (
	cfgFile        string
	socketPath     string
	networkAddress string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "zapret",
	Short: "Zapret CLI client",
	Long:  `Command-line interface for controlling the zapret daemon.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().StringVarP(&socketPath, "socket", "s", "", "unix socket path (overrides config)")
	rootCmd.PersistentFlags().StringVarP(&networkAddress, "address", "a", "", "network address (overrides config and socket)")
}

// GetClient creates a Twirp client for the daemon service.
func GetClient() (daemon.ZapretDaemon, error) {
	var httpClient *http.Client
	var baseURL string

	// Priority: network address flag > socket flag > config file
	if networkAddress != "" {
		// Use network address
		baseURL = fmt.Sprintf("http://%s", networkAddress)
		httpClient = &http.Client{}
	} else if socketPath != "" {
		// Use socket path from flag
		httpClient = NewUnixSocketClient(socketPath)
		baseURL = "http://unix"
	} else {
		// Load from config
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}

		// Prefer network address from config, fallback to socket
		if cfg.Server.NetworkAddress != "" {
			baseURL = fmt.Sprintf("http://%s", cfg.Server.NetworkAddress)
			httpClient = &http.Client{}
		} else if cfg.Server.SocketPath != "" {
			httpClient = NewUnixSocketClient(cfg.Server.SocketPath)
			baseURL = "http://unix"
		} else {
			return nil, fmt.Errorf("no connection method configured")
		}
	}

	client := daemon.NewZapretDaemonProtobufClient(baseURL, httpClient)
	return client, nil
}

// NewUnixSocketClient creates an HTTP client that connects via Unix socket.
func NewUnixSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: UnixDialer(socketPath),
		},
	}
}
