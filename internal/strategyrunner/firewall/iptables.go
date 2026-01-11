//go:build linux

package firewall

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
)

// IptablesFirewall implements Firewall using iptables.
type IptablesFirewall struct {
	ipt4   *iptables.IPTables
	ipt6   *iptables.IPTables
	config *Config
	rules  []string // Track rule specs for cleanup
	mu     sync.Mutex
}

// NewIptablesFirewall creates a new iptables firewall instance.
func NewIptablesFirewall(cfg *Config) (*IptablesFirewall, error) {
	ipt4, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables handler (IPv4): %w", err)
	}

	ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables handler (IPv6): %w", err)
	}

	return &IptablesFirewall{
		ipt4:   ipt4,
		ipt6:   ipt6,
		config: cfg,
		rules:  []string{},
	}, nil
}

// Setup creates the iptables chain and links it to OUTPUT.
func (i *IptablesFirewall) Setup(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	chainName := "zapret_output"

	// Create custom chain for both IPv4 and IPv6
	for _, ipt := range []*iptables.IPTables{i.ipt4, i.ipt6} {
		// Try to create chain (might already exist)
		if err := ipt.NewChain("filter", chainName); err != nil {
			// Chain might already exist, that's ok
			if !strings.Contains(err.Error(), "File exists") {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		// Add jump rule from OUTPUT to zapret_output
		spec := []string{"-j", chainName}
		if err := ipt.AppendUnique("filter", "OUTPUT", spec...); err != nil {
			// Rule might already exist, that's ok
			if !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("failed to add jump rule: %w", err)
			}
		}
	}

	return nil
}

// AddRule adds a firewall rule.
func (i *IptablesFirewall) AddRule(ctx context.Context, rule *Rule) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	chainName := "zapret_output"

	// Build rule specification
	spec := []string{
		"-p", rule.Protocol,
	}

	// Add interface if specified
	if rule.Interface != "" {
		spec = append(spec, "-o", rule.Interface)
	}

	// Add port matching
	portStr := buildIptablesPorts(rule.Ports)
	spec = append(spec, "--dport", portStr)

	// Add NFQUEUE target
	spec = append(spec,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", rule.QueueNum),
		"--queue-bypass",
	)

	// Add rule to both IPv4 and IPv6
	for _, ipt := range []*iptables.IPTables{i.ipt4, i.ipt6} {
		if err := ipt.Append("filter", chainName, spec...); err != nil {
			return fmt.Errorf("failed to add iptables rule: %w", err)
		}
	}

	i.rules = append(i.rules, strings.Join(spec, " "))

	return nil
}

// RemoveAll removes all rules and cleans up the firewall setup.
func (i *IptablesFirewall) RemoveAll(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	chainName := "zapret_output"
	var errs []string

	// For both IPv4 and IPv6
	for _, ipt := range []*iptables.IPTables{i.ipt4, i.ipt6} {
		// Flush the custom chain
		if err := ipt.ClearChain("filter", chainName); err != nil {
			// Chain might not exist, that's ok
			if !strings.Contains(err.Error(), "No such file") {
				errs = append(errs, fmt.Sprintf("failed to clear chain: %v", err))
			}
		}

		// Remove the jump rule from OUTPUT to zapret_output
		spec := []string{"-j", chainName}
		if err := ipt.DeleteIfExists("filter", "OUTPUT", spec...); err != nil {
			// Rule might not exist, that's ok
		}

		// Delete the custom chain
		if err := ipt.DeleteChain("filter", chainName); err != nil {
			// Chain might not exist, that's ok
			if !strings.Contains(err.Error(), "No such file") {
				errs = append(errs, fmt.Sprintf("failed to delete chain: %v", err))
			}
		}
	}

	i.rules = nil

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", strings.Join(errs, "; "))
	}

	return nil
}

// Close closes the iptables firewall.
func (i *IptablesFirewall) Close() error {
	return nil
}

// buildIptablesPorts converts a port list to iptables format.
func buildIptablesPorts(ports []string) string {
	return strings.Join(ports, ",")
}
