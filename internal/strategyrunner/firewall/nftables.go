//go:build linux

package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// NftablesFirewall implements Firewall using nftables command-line tool.
type NftablesFirewall struct {
	config *Config
	rules  []string // Track rule strings for cleanup
	mu     sync.Mutex
}

// NewNftablesFirewall creates a new nftables firewall instance.
func NewNftablesFirewall(cfg *Config) (*NftablesFirewall, error) {
	return &NftablesFirewall{
		config: cfg,
		rules:  []string{},
	}, nil
}

// Setup creates the nftables table and chain.
func (n *NftablesFirewall) Setup(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Create table: nft add table inet zapretunix
	cmd := exec.CommandContext(ctx, "nft", "add", "table", n.config.TableName)
	if err := cmd.Run(); err != nil {
		// Table might already exist, that's ok
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// Create chain: nft add chain inet zapretunix output { type filter hook output priority 0; }
	cmd = exec.CommandContext(ctx, "nft", "add", "chain", n.config.TableName,
		n.config.ChainName,
		fmt.Sprintf("{ type filter hook output priority 0; }"))
	if err := cmd.Run(); err != nil {
		// Chain might already exist, that's ok
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	return nil
}

// AddRule adds a firewall rule.
func (n *NftablesFirewall) AddRule(ctx context.Context, rule *Rule) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Build port string
	portStr := strings.Join(rule.Ports, ",")
	if len(rule.Ports) > 1 {
		portStr = "{" + portStr + "}"
	}

	// Build rule expression
	var ruleExpr string

	if rule.Interface != "" {
		ruleExpr = fmt.Sprintf("oifname \"%s\" %s dport %s counter queue num %d bypass",
			rule.Interface, rule.Protocol, portStr, rule.QueueNum)
	} else {
		ruleExpr = fmt.Sprintf("%s dport %s counter queue num %d bypass",
			rule.Protocol, portStr, rule.QueueNum)
	}

	// Add rule: nft add rule inet zapretunix output [expression]
	cmd := exec.CommandContext(ctx, "nft", "add", "rule", n.config.TableName,
		n.config.ChainName, ruleExpr)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	n.rules = append(n.rules, ruleExpr)

	return nil
}

// RemoveAll removes all rules and cleans up the firewall setup.
func (n *NftablesFirewall) RemoveAll(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var errs []string

	// Delete table (cascades to delete chain and rules)
	// nft delete table inet zapretunix
	cmd := exec.CommandContext(ctx, "nft", "delete", "table", n.config.TableName)
	if err := cmd.Run(); err != nil {
		// Table might not exist, that's ok
		if !strings.Contains(err.Error(), "No such file") {
			errs = append(errs, fmt.Sprintf("failed to delete table: %v", err))
		}
	}

	n.rules = nil

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", strings.Join(errs, "; "))
	}

	return nil
}

// Close closes the nftables firewall.
func (n *NftablesFirewall) Close() error {
	return nil
}
