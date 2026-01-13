package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/twitchtv/twirp"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/rpc/daemon"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get strategy runner status",
	Long:  `Get the current status of the strategy runner.`,
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	client, err := GetClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.GetStatus(ctx, &daemon.StatusRequest{})
	if err != nil {
		// Handle Twirp errors with more context
		if twerr, ok := err.(twirp.Error); ok {
			return fmt.Errorf("get status failed: %s (code: %s)", twerr.Msg(), twerr.Code())
		}
		return fmt.Errorf("get status failed: %w", err)
	}

	// Print status
	runningStr := "❌ not running"
	if resp.Running {
		runningStr = "✓ running"
	}

	fmt.Printf("Status:             %s\n", runningStr)

	// Parse and display start time with uptime
	if resp.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, resp.StartTime)
		if err == nil {
			uptime := time.Since(startTime)
			fmt.Printf("Started:            %s (%s)\n", resp.StartTime, formatUptime(uptime))
		} else {
			fmt.Printf("Started:            %s\n", resp.StartTime)
		}
	}

	fmt.Printf("Strategy File:      %s\n", resp.StrategyFile)
	fmt.Printf("Active Queues:      %d\n", resp.ActiveQueues)
	fmt.Printf("Active Processes:   %d\n", resp.ActiveProcesses)
	fmt.Printf("Firewall Backend:   %s\n", resp.FirewallBackend)

	return nil
}

// formatUptime formats a duration into a human-readable uptime string.
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
