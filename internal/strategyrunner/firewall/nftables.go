//go:build linux

package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// NftablesFirewall implements Firewall using nft CLI.
type NftablesFirewall struct {
	config     *Config
	mu         sync.Mutex
	ruleCount  int
	tableName  string
	chainName  string
	comment    string
}

// NewNftablesFirewall creates a new nftables firewall instance.
func NewNftablesFirewall(cfg *Config) (*NftablesFirewall, error) {
	// Check if nft is available
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft command not found: %w", err)
	}

	return &NftablesFirewall{
		config:    cfg,
		tableName: cfg.TableName,
		chainName: cfg.ChainName,
		comment:   "Added by zapret-ng",
	}, nil
}

// Setup creates the nftables table and chain.
func (n *NftablesFirewall) Setup(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Check if table exists and clean it up
	if err := n.runCommand("nft", "list", "tables"); err == nil {
		// Check if our table exists
		output, _ := exec.Command("nft", "list", "tables").Output()
		if strings.Contains(string(output), n.tableName) {
			// Delete existing table (this will cascade to chains and rules)
			_ = n.runCommand("nft", "delete", "table", n.tableName)
		}
	}

	// Create inet table (handles both IPv4 and IPv6)
	if err := n.runCommand("nft", "add", "table", n.tableName); err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Create output chain with filter hook
	chainDef := fmt.Sprintf("{ type filter hook output priority 0; }")
	if err := n.runCommand("nft", "add", "chain", n.tableName, n.chainName, chainDef); err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}

	return nil
}

// runCommand executes nft command
func (n *NftablesFirewall) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s: %w\nOutput: %s", strings.Join(append([]string{name}, args...), " "), err, string(output))
	}
	return nil
}

// AddRule adds a firewall rule using nft CLI.
func (n *NftablesFirewall) AddRule(ctx context.Context, rule *Rule) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Build the nftables rule string
	var ruleParts []string

	// Add interface match if specified and not "any"
	if rule.Interface != "" && rule.Interface != "any" {
		ruleParts = append(ruleParts, fmt.Sprintf(`oifname "%s"`, rule.Interface))
	}

	// Add protocol match
	ruleParts = append(ruleParts, rule.Protocol)

	// Add port match - build port specification
	portSpec, err := n.buildPortSpec(rule.Ports)
	if err != nil {
		return fmt.Errorf("failed to build port specification: %w", err)
	}
	ruleParts = append(ruleParts, fmt.Sprintf("dport %s", portSpec))

	// Add counter
	ruleParts = append(ruleParts, "counter")

	// Add queue with bypass
	ruleParts = append(ruleParts, fmt.Sprintf("queue num %d bypass", rule.QueueNum))

	// Add comment
	ruleParts = append(ruleParts, fmt.Sprintf(`comment "%s"`, n.comment))

	// Build full rule
	ruleStr := strings.Join(ruleParts, " ")

	// Execute nft command
	if err := n.runCommand("nft", "add", "rule", n.tableName, n.chainName, ruleStr); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	n.ruleCount++
	return nil
}

// buildPortSpec builds port specification for nftables rule.
// Supports: single port (80), range (1024-2048), comma-separated (80,443,1024-2048).
func (n *NftablesFirewall) buildPortSpec(ports []string) (string, error) {
	if len(ports) == 0 {
		return "", fmt.Errorf("no ports specified")
	}

	// Join all port specs and parse
	var allPorts []string
	for _, portSpec := range ports {
		// Split by comma to handle "80,443,1024-2048" format
		parts := strings.Split(portSpec, ",")
		for _, part := range parts {
			allPorts = append(allPorts, strings.TrimSpace(part))
		}
	}

	if len(allPorts) == 0 {
		return "", fmt.Errorf("no ports after parsing")
	}

	// If single port or range, return as-is
	if len(allPorts) == 1 {
		return allPorts[0], nil
	}

	// Multiple ports/ranges - use set notation { }
	return fmt.Sprintf("{ %s }", strings.Join(allPorts, ", ")), nil
}

// RemoveAll removes all rules and cleans up the firewall setup.
func (n *NftablesFirewall) RemoveAll(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Check if table exists
	output, err := exec.Command("nft", "list", "tables").Output()
	if err != nil {
		// nft command failed, nothing to clean
		return nil
	}

	if !strings.Contains(string(output), n.tableName) {
		// Table doesn't exist, nothing to clean
		return nil
	}

	// Check if chain exists and delete rules with our comment
	chainOutput, err := exec.Command("nft", "-a", "list", "chain", n.tableName, n.chainName).Output()
	if err == nil {
		// Parse handles of rules with our comment
		lines := strings.Split(string(chainOutput), "\n")
		for _, line := range lines {
			if strings.Contains(line, n.comment) {
				// Extract handle number from line like: "... handle 42"
				fields := strings.Fields(line)
				for i, field := range fields {
					if field == "handle" && i+1 < len(fields) {
						handle := fields[i+1]
						_ = n.runCommand("nft", "delete", "rule", n.tableName, n.chainName, "handle", handle)
					}
				}
			}
		}
	}

	// Delete chain and table
	_ = n.runCommand("nft", "delete", "chain", n.tableName, n.chainName)
	_ = n.runCommand("nft", "delete", "table", n.tableName)

	n.ruleCount = 0
	return nil
}

// Close closes the nftables firewall and removes all rules.
func (n *NftablesFirewall) Close() error {
	return n.RemoveAll(context.Background())
}
