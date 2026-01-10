package daemonserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/twitchtv/twirp"
	"github.com/Sergeydigl3/zapret-nix/rpc/daemon"
)

// Server implements the ZapretDaemon service.
type Server struct {
	logger       *slog.Logger
	startTime    time.Time
	restartCount int
}

// NewServer creates a new daemon server instance.
func NewServer(logger *slog.Logger) *Server {
	return &Server{
		logger:    logger,
		startTime: time.Now(),
	}
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

	// Check if daemon is busy (this is a placeholder - implement actual logic)
	isBusy := false // TODO: implement actual busy check
	if isBusy && !req.Force {
		s.logger.Warn("restart rejected: daemon is busy")
		return nil, twirp.NewError(twirp.FailedPrecondition, "daemon is busy, use force=true to override")
	}

	// Perform restart logic
	restartedAt := time.Now()
	s.restartCount++
	s.startTime = restartedAt

	s.logger.Info("daemon restarted successfully",
		slog.Time("restarted_at", restartedAt),
		slog.Int("total_restarts", s.restartCount),
	)

	// In a real implementation, you would trigger actual restart logic here
	// For example: reload configuration, restart workers, etc.

	return &daemon.RestartResponse{
		Message:     fmt.Sprintf("daemon restarted successfully (restart #%d)", s.restartCount),
		RestartedAt: restartedAt.Format(time.RFC3339),
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

// NewTwirpServer creates a new Twirp HTTP handler for the daemon service.
func NewTwirpServer(logger *slog.Logger) daemon.TwirpServer {
	server := NewServer(logger)

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

	return daemon.NewZapretDaemonServer(server, twirp.WithServerHooks(hooks))
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
