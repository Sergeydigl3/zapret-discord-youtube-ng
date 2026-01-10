package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/twitchtv/twirp"
	"github.com/Sergeydigl3/zapret-nix/rpc/daemon"
)

var (
	forceRestart bool
)

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the zapret daemon",
	Long:  `Send a restart command to the zapret daemon service.`,
	RunE:  runRestart,
}

func init() {
	rootCmd.AddCommand(restartCmd)
	restartCmd.Flags().BoolVarP(&forceRestart, "force", "f", false, "force restart even if daemon is busy")
}

func runRestart(cmd *cobra.Command, args []string) error {
	client, err := GetClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &daemon.RestartRequest{
		Force: forceRestart,
	}

	resp, err := client.Restart(ctx, req)
	if err != nil {
		// Handle Twirp errors with more context
		if twerr, ok := err.(twirp.Error); ok {
			return fmt.Errorf("restart failed: %s (code: %s)", twerr.Msg(), twerr.Code())
		}
		return fmt.Errorf("restart failed: %w", err)
	}

	fmt.Println("✓", resp.Message)
	fmt.Printf("Restarted at: %s\n", resp.RestartedAt)

	return nil
}
