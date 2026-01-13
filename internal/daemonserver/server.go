package daemonserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/twitchtv/twirp"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/internal/config"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/internal/strategyrunner"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/rpc/daemon"
)

// Server implements the ZapretDaemon service.
type Server struct {
	logger         *slog.Logger
	startTime      time.Time
	restartCount   int
	strategyRunner *strategyrunner.Runner
}

// NewServer creates a new daemon server instance.
func NewServer(logger *slog.Logger, cfg *config.Config) (*Server, error) {
	var runner *strategyrunner.Runner
	var err error

	if cfg.StrategyRunner.Enabled {
		runner, err = strategyrunner.NewRunner(&cfg.StrategyRunner, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create strategy runner: %w", err)
		}
	}

	return &Server{
		logger:         logger,
		startTime:      time.Now(),
		strategyRunner: runner,
	}, nil
}

// Restart implements the Restart RPC method.
func (s *Server) Restart(ctx context.Context, req *daemon.RestartRequest) (*daemon.RestartResponse, error) {
	s.logger.Info("restart requested",
		slog.Bool("force", req.Force),
		slog.Int("restart_count", s.restartCount),
	)

	// Validate request
	if req == nil {
		return nil, twirp.RequiredArgumentError("request")
	}

	// If strategy runner is enabled, restart it
	if s.strategyRunner != nil {
		if err := s.strategyRunner.Restart(ctx); err != nil {
			s.logger.Error("failed to restart strategy runner", slog.Any("error", err))
			return nil, twirp.InternalErrorWith(err)
		}
	}

	// Perform restart tracking
	restartedAt := time.Now()
	s.restartCount++
	s.startTime = restartedAt

	s.logger.Info("strategy runner restarted successfully",
		slog.Time("restarted_at", restartedAt),
		slog.Int("total_restarts", s.restartCount),
	)

	return &daemon.RestartResponse{
		Message:     fmt.Sprintf("strategy runner restarted successfully (restart #%d)", s.restartCount),
		RestartedAt: restartedAt.Format(time.RFC3339),
	}, nil
}

// GetStatus implements the GetStatus RPC method.
func (s *Server) GetStatus(ctx context.Context, req *daemon.StatusRequest) (*daemon.StatusResponse, error) {
	if s.strategyRunner == nil {
		return &daemon.StatusResponse{
			Running: false,
		}, nil
	}

	status := s.strategyRunner.GetStatus()

	var startTimeStr string
	if !status.StartTime.IsZero() {
		startTimeStr = status.StartTime.Format(time.RFC3339)
	}

	return &daemon.StatusResponse{
		Running:         status.Running,
		StrategyFile:    status.StrategyFile,
		ActiveQueues:    int32(status.ActiveQueues),
		ActiveProcesses: int32(status.ActiveProcesses),
		FirewallBackend: status.FirewallBackend,
		StartTime:       startTimeStr,
	}, nil
}

// GetStartTime returns when the server was started.
func (s *Server) GetStartTime() time.Time {
	return s.startTime
}

// GetRestartCount returns the number of times the server has been restarted.
func (s *Server) GetRestartCount() int {
	return s.restartCount
}

// Shutdown performs graceful shutdown and cleanup of resources.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down daemon server")

	if s.strategyRunner != nil {
		if err := s.strategyRunner.Stop(ctx); err != nil {
			s.logger.Error("failed to stop strategy runner during shutdown", slog.Any("error", err))
			return err
		}
	}

	s.logger.Info("daemon server shutdown complete")
	return nil
}

// NewTwirpServer creates a new Twirp HTTP handler for the daemon service.
// It returns both the Twirp server and the underlying Server instance for cleanup.
func NewTwirpServer(logger *slog.Logger, cfg *config.Config) (daemon.TwirpServer, *Server, error) {
	server, err := NewServer(logger, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Start strategy runner if enabled
	if server.strategyRunner != nil {
		if err := server.strategyRunner.Start(context.Background()); err != nil {
			logger.Error("failed to start strategy runner", slog.Any("error", err))
			return nil, nil, err
		}
	}

	// Create Twirp server with hooks for logging
	hooks := &twirp.ServerHooks{
		RequestReceived: func(ctx context.Context) (context.Context, error) {
			logger.Debug("request received")
			return ctx, nil
		},
		RequestRouted: func(ctx context.Context) (context.Context, error) {
			method, _ := twirp.MethodName(ctx)
			logger.Debug("request routed", slog.String("method", method))
			return ctx, nil
		},
		ResponsePrepared: func(ctx context.Context) context.Context {
			logger.Debug("response prepared")
			return ctx
		},
		Error: func(ctx context.Context, err twirp.Error) context.Context {
			method, _ := twirp.MethodName(ctx)
			logger.Error("twirp error",
				slog.String("method", method),
				slog.String("code", string(err.Code())),
				slog.String("msg", err.Msg()),
			)
			return ctx
		},
	}

	return daemon.NewZapretDaemonServer(server, twirp.WithServerHooks(hooks)), server, nil
}

// InitLogger initializes a structured logger with the specified level and format.
func InitLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
