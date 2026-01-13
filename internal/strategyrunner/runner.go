package strategyrunner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/Sergeydigl3/zapret-discord-youtube-ng/internal/config"
	"github.com/Sergeydigl3/zapret-discord-youtube-ng/internal/strategyrunner/firewall"
)

// Runner orchestrates the strategy runner lifecycle.
type Runner struct {
	config         *Config
	mainCfg        *config.StrategyRunnerConfig
	logger         *slog.Logger
	parser         *Parser
	fw             firewall.Firewall
	procManager    *ProcessManager
	watcher        *ConfigWatcher
	mu             sync.RWMutex
	running        bool
	lastParsedLen  int
}

// Status represents the runner status.
type Status struct {
	Running         bool
	StrategyFile    string
	ActiveQueues    int
	ActiveProcesses int
	FirewallBackend string
}

// NewRunner creates a new strategy runner.
func NewRunner(mainCfg *config.StrategyRunnerConfig, logger *slog.Logger) (*Runner, error) {
	// Load strategy config
	cfg, err := LoadStrategyConfig(mainCfg.ConfigPath)
	if err != nil {
		return nil, err
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Store binary path and other settings
	cfg.BinaryPath = mainCfg.NFQWSBinary
	cfg.ConfigPath = mainCfg.ConfigPath
	cfg.Watch = mainCfg.Watch

	// Create firewall instance
	fw, err := firewall.NewFirewall(&firewall.Config{
		Backend:   cfg.Firewall.Backend,
		TableName: cfg.Firewall.TableName,
		ChainName: cfg.Firewall.ChainName,
		Interface: cfg.Interface,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall: %w", err)
	}

	// Create parser
	parser := NewParser(
		"/usr/bin",
		"/etc/zapret-ng/lists",
		cfg.GameFilterPorts,
		cfg.GameFilter,
		logger,
	)

	// Create process manager
	procManager := NewProcessManager(mainCfg.NFQWSBinary, logger)

	return &Runner{
		config:      cfg,
		mainCfg:     mainCfg,
		logger:      logger,
		parser:      parser,
		fw:          fw,
		procManager: procManager,
		running:     false,
	}, nil
}

// Start starts the strategy runner.
func (r *Runner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return errors.New("strategy runner already running")
	}

	r.logger.Info("starting strategy runner",
		slog.String("interface", r.config.Interface),
		slog.String("strategy_file", r.config.StrategyFile),
		slog.String("firewall", r.config.Firewall.Backend),
	)

	// Track if we need to cleanup on error
	var firewallSetup bool
	defer func() {
		// If we had an error and firewall was setup, clean it up
		if !r.running && firewallSetup {
			r.logger.Info("startup failed, cleaning up firewall rules")
			cleanupCtx := context.Background()
			if err := r.fw.RemoveAll(cleanupCtx); err != nil {
				r.logger.Error("failed to cleanup firewall rules", slog.Any("error", err))
			}
			// Also stop any processes that might have started
			if err := r.procManager.StopAll(); err != nil {
				r.logger.Error("failed to stop processes during cleanup", slog.Any("error", err))
			}
		}
	}()

	// 1. Parse strategy file
	r.logger.Info("parsing strategy file", slog.String("path", r.config.StrategyFile))
	strategy, err := r.parser.Parse(r.config.StrategyFile)
	if err != nil {
		return fmt.Errorf("parse failed: %w", err)
	}

	r.lastParsedLen = len(strategy.Rules)
	r.logger.Info("parsed strategy rules", slog.Int("count", len(strategy.Rules)))

	// 2. Setup firewall
	r.logger.Info("setting up firewall",
		slog.String("backend", r.config.Firewall.Backend),
		slog.String("table", r.config.Firewall.TableName),
		slog.String("chain", r.config.Firewall.ChainName),
	)
	if err := r.fw.Setup(ctx); err != nil {
		return fmt.Errorf("firewall setup failed: %w", err)
	}
	firewallSetup = true

	// 3. Add firewall rules
	for _, rule := range strategy.Rules {
		fwRule := r.convertToFirewallRule(rule)
		r.logger.Debug("adding firewall rule",
			slog.String("protocol", rule.Protocol),
			slog.String("ports", rule.Ports),
			slog.Int("queue", rule.QueueNum),
		)
		if err := r.fw.AddRule(ctx, fwRule); err != nil {
			return fmt.Errorf("add rule failed: %w", err)
		}
	}

	// 4. Start nfqws processes
	r.logger.Info("starting nfqws processes", slog.Int("count", len(strategy.Rules)))
	for _, rule := range strategy.Rules {
		procCfg := &ProcessConfig{
			QueueNum: rule.QueueNum,
			Args:     parseNFQWSArgs(rule.NFQWSArgs),
		}
		if err := r.procManager.Start(procCfg); err != nil {
			// Log error but continue with other processes
			r.logger.Error("failed to start process",
				slog.Int("queue", rule.QueueNum),
				slog.Any("error", err),
			)
			// Don't return error - try to start the rest
		}
	}

	// 5. Start config watcher if enabled
	if r.config.Watch {
		r.logger.Info("starting config file watcher", slog.String("path", r.config.ConfigPath))
		watcher, err := NewConfigWatcher(r.config.ConfigPath, func() {
			r.logger.Info("config changed, restarting strategy runner")
			ctx := context.Background()
			if err := r.Restart(ctx); err != nil {
				r.logger.Error("failed to restart strategy runner", slog.Any("error", err))
			}
		}, r.logger)
		if err != nil {
			r.logger.Warn("failed to create config watcher",
				slog.String("path", r.config.ConfigPath),
				slog.Any("error", err),
			)
		} else {
			r.watcher = watcher
			if err := r.watcher.Start(); err != nil {
				r.logger.Warn("failed to start config watcher", slog.Any("error", err))
			}
		}
	}

	r.running = true
	r.logger.Info("strategy runner started successfully",
		slog.Int("rules", len(strategy.Rules)),
		slog.Int("processes", r.procManager.Count()),
	)

	return nil
}

// Stop stops the strategy runner.
func (r *Runner) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		r.logger.Info("strategy runner not running")
		return nil
	}

	r.logger.Info("stopping strategy runner")

	var errs []error

	// 1. Stop watcher
	if r.watcher != nil {
		r.logger.Info("stopping config watcher")
		if err := r.watcher.Stop(); err != nil {
			r.logger.Warn("error stopping watcher", slog.Any("error", err))
			errs = append(errs, err)
		}
		r.watcher = nil
	}

	// 2. Stop nfqws processes
	r.logger.Info("stopping nfqws processes", slog.Int("count", r.procManager.Count()))
	if err := r.procManager.StopAll(); err != nil {
		r.logger.Warn("error stopping processes", slog.Any("error", err))
		errs = append(errs, err)
	}

	// 3. Remove firewall rules
	r.logger.Info("removing firewall rules")
	if err := r.fw.RemoveAll(ctx); err != nil {
		r.logger.Warn("error removing firewall rules", slog.Any("error", err))
		errs = append(errs, err)
	}

	r.running = false
	r.logger.Info("strategy runner stopped")

	if len(errs) > 0 {
		return fmt.Errorf("stop errors: %v", errs)
	}

	return nil
}

// Restart restarts the strategy runner with new configuration.
func (r *Runner) Restart(ctx context.Context) error {
	r.logger.Info("restarting strategy runner")

	// Stop existing runner
	if err := r.Stop(ctx); err != nil {
		r.logger.Error("error stopping runner", slog.Any("error", err))
		// Continue anyway
	}

	// Reload configuration
	r.logger.Info("reloading configuration", slog.String("path", r.mainCfg.ConfigPath))
	cfg, err := LoadStrategyConfig(r.mainCfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Validate new config
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("new config validation failed: %w", err)
	}

	cfg.BinaryPath = r.mainCfg.NFQWSBinary
	cfg.ConfigPath = r.mainCfg.ConfigPath
	cfg.Watch = r.mainCfg.Watch

	// Update runner config
	r.mu.Lock()
	r.config = cfg
	r.mu.Unlock()

	// Recreate firewall instance with new config
	fw, err := firewall.NewFirewall(&firewall.Config{
		Backend:   cfg.Firewall.Backend,
		TableName: cfg.Firewall.TableName,
		ChainName: cfg.Firewall.ChainName,
		Interface: cfg.Interface,
	})
	if err != nil {
		return fmt.Errorf("failed to create firewall: %w", err)
	}

	r.mu.Lock()
	r.fw = fw
	r.mu.Unlock()

	// Start with new configuration
	return r.Start(ctx)
}

// GetStatus returns the current runner status.
func (r *Runner) GetStatus() *Status {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return &Status{
		Running:         r.running,
		StrategyFile:    r.config.StrategyFile,
		ActiveQueues:    r.lastParsedLen,
		ActiveProcesses: r.procManager.Count(),
		FirewallBackend: r.config.Firewall.Backend,
	}
}

// Helper functions

// convertToFirewallRule converts a parsed rule to a firewall rule.
func (r *Runner) convertToFirewallRule(rule ParsedRule) *firewall.Rule {
	interface_ := ""
	if r.config.Interface != "any" {
		interface_ = r.config.Interface
	}

	return &firewall.Rule{
		Protocol:  rule.Protocol,
		Ports:     splitPorts(rule.Ports),
		QueueNum:  rule.QueueNum,
		Interface: interface_,
		Comment:   "Added by zapret",
	}
}

// splitPorts splits a port string into a slice.
func splitPorts(portStr string) []string {
	// Handle individual ports and ranges as-is
	return []string{portStr}
}

// parseNFQWSArgs parses nfqws arguments from a string.
func parseNFQWSArgs(argsStr string) []string {
	// Simple split on spaces, preserving quoted strings
	var args []string
	var current string
	inQuotes := false

	for _, ch := range argsStr {
		switch ch {
		case '"':
			inQuotes = !inQuotes
		case ' ':
			if inQuotes {
				current += string(ch)
			} else if current != "" {
				args = append(args, current)
				current = ""
			}
		default:
			current += string(ch)
		}
	}

	if current != "" {
		args = append(args, current)
	}

	return args
}
