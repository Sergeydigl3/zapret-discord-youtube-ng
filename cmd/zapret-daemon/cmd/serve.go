package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/internal/config"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/internal/daemonserver"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the zapret daemon service",
	Long:  `Start the zapret daemon service and listen for control commands.`,
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load(GetConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Initialize logger
	logger := daemonserver.InitLogger(cfg.Logging.Level, cfg.Logging.Format)
	logger.Info("starting zapret daemon",
		slog.String("socket_path", cfg.Server.SocketPath),
		slog.String("network_address", cfg.Server.NetworkAddress),
	)

	// Create Twirp server with config
	twirpServer, daemonSrv, err := daemonserver.NewTwirpServer(logger, cfg)
	if err != nil {
		return fmt.Errorf("failed to create twirp server: %w", err)
	}

	// Create HTTP server
	httpServer := &http.Server{
		Handler:      twirpServer,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup listeners
	var listeners []net.Listener

	// Unix socket listener
	if cfg.Server.SocketPath != "" {
		// Create parent directory for socket if it doesn't exist
		socketDir := filepath.Dir(cfg.Server.SocketPath)
		if err := os.MkdirAll(socketDir, 0755); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}

		// Remove existing socket file if it exists
		if err := os.RemoveAll(cfg.Server.SocketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket: %w", err)
		}

		unixListener, err := net.Listen("unix", cfg.Server.SocketPath)
		if err != nil {
			return fmt.Errorf("failed to create unix socket listener: %w", err)
		}
		listeners = append(listeners, unixListener)

		// Set socket permissions
		if err := os.Chmod(cfg.Server.SocketPath, cfg.Server.SocketPermissions); err != nil {
			logger.Warn("failed to set socket permissions",
				slog.String("path", cfg.Server.SocketPath),
				slog.String("error", err.Error()),
			)
		}

		logger.Info("listening on unix socket", slog.String("path", cfg.Server.SocketPath))
	}

	// Network listener
	if cfg.Server.NetworkAddress != "" {
		tcpListener, err := net.Listen("tcp", cfg.Server.NetworkAddress)
		if err != nil {
			return fmt.Errorf("failed to create network listener: %w", err)
		}
		listeners = append(listeners, tcpListener)

		logger.Info("listening on network", slog.String("address", cfg.Server.NetworkAddress))
	}

	// Start serving on all listeners
	errChan := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func(l net.Listener) {
			if err := httpServer.Serve(l); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("server error on %s: %w", l.Addr(), err)
			}
		}(listener)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		// Server error occurred - cleanup before returning
		logger.Error("server error occurred, cleaning up", slog.String("error", err.Error()))
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if cleanupErr := daemonSrv.Shutdown(cleanupCtx); cleanupErr != nil {
			logger.Error("cleanup error", slog.String("error", cleanupErr.Error()))
		}
		return err
	case sig := <-sigChan:
		logger.Info("received shutdown signal", slog.String("signal", sig.String()))
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger.Info("shutting down gracefully...")

	// First, shutdown the daemon server to cleanup resources (firewall rules, processes)
	if err := daemonSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("daemon shutdown error", slog.String("error", err.Error()))
		// Continue with HTTP server shutdown even if daemon shutdown fails
	}

	// Then shutdown HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("http server shutdown error", slog.String("error", err.Error()))
		return err
	}

	// Cleanup unix socket
	if cfg.Server.SocketPath != "" {
		if err := os.RemoveAll(cfg.Server.SocketPath); err != nil {
			logger.Warn("failed to remove socket file",
				slog.String("path", cfg.Server.SocketPath),
				slog.String("error", err.Error()),
			)
		}
	}

	logger.Info("daemon stopped")
	return nil
}
