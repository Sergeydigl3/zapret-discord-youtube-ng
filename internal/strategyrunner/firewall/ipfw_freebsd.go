//go:build freebsd

package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// IpfwFirewall implements Firewall using FreeBSD ipfw.
type IpfwFirewall struct {
	config   *Config
	ruleNums []int // Track rule numbers for cleanup
	nextRule int   // Next rule number to use
	mu       sync.Mutex
}

// NewIpfwFirewall creates a new ipfw firewall instance.
func NewIpfwFirewall(cfg *Config) (*IpfwFirewall, error) {
	return &IpfwFirewall{
		config:   cfg,
		ruleNums: []int{},
		nextRule: 100, // Start from rule 100
	}, nil
}

// NewFirewall creates a new firewall instance for FreeBSD.
func NewFirewall(cfg *Config) (Firewall, error) {
	return NewIpfwFirewall(cfg)
}

// Setup loads ipfw and ipdivert kernel modules.
func (f *IpfwFirewall) Setup(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Load ipfw kernel module (ignore error if already loaded)
	exec.CommandContext(ctx, "kldload", "ipfw").Run()

	// Load ipdivert kernel module (ignore error if already loaded)
	exec.CommandContext(ctx, "kldload", "ipdivert").Run()

	return nil
}

// AddRule adds an ipfw divert rule.
func (f *IpfwFirewall) AddRule(ctx context.Context, rule *Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	ruleNum := f.nextRule
	f.nextRule++

	// Build port string for ipfw
	portStr := buildIpfwPorts(rule.Ports)

	// Build ipfw rule:
	// ipfw add <num> divert <port> <proto> from any to any <ports> out not diverted not sockarg [xmit <iface>]
	args := []string{
		"add", fmt.Sprintf("%d", ruleNum),
		"divert", fmt.Sprintf("%d", rule.QueueNum),
		rule.Protocol,
		"from", "any", "to", "any",
		portStr,
		"out", "not", "diverted", "not", "sockarg",
	}

	// Add interface if specified
	if rule.Interface != "" {
		args = append(args, "xmit", rule.Interface)
	}

	cmd := exec.CommandContext(ctx, "ipfw", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add ipfw rule: %w, output: %s", err, string(output))
	}

	f.ruleNums = append(f.ruleNums, ruleNum)

	return nil
}

// RemoveAll removes all ipfw rules created by this instance.
func (f *IpfwFirewall) RemoveAll(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var errs []string

	// Delete each rule we created
	for _, ruleNum := range f.ruleNums {
		cmd := exec.CommandContext(ctx, "ipfw", "delete", fmt.Sprintf("%d", ruleNum))
		if err := cmd.Run(); err != nil {
			errs = append(errs, fmt.Sprintf("failed to delete rule %d: %v", ruleNum, err))
		}
	}

	f.ruleNums = nil

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", strings.Join(errs, "; "))
	}

	return nil
}

// Close closes the ipfw firewall.
func (f *IpfwFirewall) Close() error {
	return nil
}

// buildIpfwPorts converts a port list to ipfw format.
func buildIpfwPorts(ports []string) string {
	if len(ports) == 1 {
		return ports[0]
	}
	// ipfw uses comma-separated ports or ranges like "80,443" or "50000-50100"
	return strings.Join(ports, ",")
}
