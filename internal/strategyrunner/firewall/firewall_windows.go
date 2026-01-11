//go:build windows

package firewall

import "context"

// NoopFirewall is a no-op firewall for Windows.
// On Windows, WinDivert handles packet capture without firewall rules.
type NoopFirewall struct{}

// NewFirewall creates a no-op firewall on Windows.
func NewFirewall(cfg *Config) (Firewall, error) {
	return &NoopFirewall{}, nil
}

func (n *NoopFirewall) Setup(ctx context.Context) error {
	return nil
}

func (n *NoopFirewall) AddRule(ctx context.Context, rule *Rule) error {
	return nil
}

func (n *NoopFirewall) RemoveAll(ctx context.Context) error {
	return nil
}

func (n *NoopFirewall) Close() error {
	return nil
}
