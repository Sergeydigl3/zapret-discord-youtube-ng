//go:build linux

package firewall

import "fmt"

// NewFirewall creates a new firewall instance based on the backend.
func NewFirewall(cfg *Config) (Firewall, error) {
	switch cfg.Backend {
	case "nftables":
		return NewNftablesFirewall(cfg)
	case "iptables":
		return NewIptablesFirewall(cfg)
	default:
		return nil, fmt.Errorf("unknown firewall backend: %s", cfg.Backend)
	}
}
