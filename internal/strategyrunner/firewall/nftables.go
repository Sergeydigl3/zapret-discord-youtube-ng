//go:build linux

package firewall

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NftablesFirewall implements Firewall using google/nftables library.
type NftablesFirewall struct {
	conn   *nftables.Conn
	table  *nftables.Table
	chain  *nftables.Chain
	config *Config
	rules  []*nftables.Rule
	mu     sync.Mutex
}

// NewNftablesFirewall creates a new nftables firewall instance.
func NewNftablesFirewall(cfg *Config) (*NftablesFirewall, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}

	return &NftablesFirewall{
		conn:   conn,
		config: cfg,
		rules:  []*nftables.Rule{},
	}, nil
}

// Setup creates the nftables table and chain.
func (n *NftablesFirewall) Setup(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Create inet table (handles both IPv4 and IPv6)
	n.table = n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   n.config.TableName,
	})

	// Create output chain with filter hook
	n.chain = n.conn.AddChain(&nftables.Chain{
		Name:     n.config.ChainName,
		Table:    n.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to create table and chain: %w", err)
	}

	return nil
}

// AddRule adds a firewall rule.
func (n *NftablesFirewall) AddRule(ctx context.Context, rule *Rule) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.table == nil || n.chain == nil {
		return fmt.Errorf("firewall not set up, call Setup first")
	}

	// Build expressions for the rule
	exprs := []expr.Any{}

	// Add interface match if specified
	if rule.Interface != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(rule.Interface),
			},
		)
	}

	// Add protocol match (tcp or udp)
	protoNum := uint8(unix.IPPROTO_TCP)
	if rule.Protocol == "udp" {
		protoNum = uint8(unix.IPPROTO_UDP)
	}

	exprs = append(exprs,
		// Load protocol from L4 header
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{protoNum},
		},
	)

	// Add port match
	portExprs, err := buildPortMatchExprs(rule.Ports)
	if err != nil {
		return fmt.Errorf("failed to build port expressions: %w", err)
	}
	exprs = append(exprs, portExprs...)

	// Add counter
	exprs = append(exprs, &expr.Counter{})

	// Add queue target with bypass flag
	exprs = append(exprs, &expr.Queue{
		Num:  uint16(rule.QueueNum),
		Flag: expr.QueueFlagBypass,
	})

	// Add the rule
	nftRule := n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: n.chain,
		Exprs: exprs,
	})

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	n.rules = append(n.rules, nftRule)

	return nil
}

// RemoveAll removes all rules and cleans up the firewall setup.
func (n *NftablesFirewall) RemoveAll(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.table == nil {
		return nil
	}

	// Delete the entire table (cascades to chains and rules)
	n.conn.DelTable(n.table)

	if err := n.conn.Flush(); err != nil {
		// Table might not exist, that's ok
		if !strings.Contains(err.Error(), "no such file") {
			return fmt.Errorf("failed to delete table: %w", err)
		}
	}

	n.table = nil
	n.chain = nil
	n.rules = nil

	return nil
}

// Close closes the nftables firewall.
func (n *NftablesFirewall) Close() error {
	return nil
}

// ifname pads interface name to 16 bytes (IFNAMSIZ)
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// buildPortMatchExprs builds nftables expressions for port matching.
func buildPortMatchExprs(ports []string) ([]expr.Any, error) {
	exprs := []expr.Any{}

	// Load destination port into register 1
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // Destination port offset
			Len:          2, // Port is 2 bytes
		},
	)

	if len(ports) == 1 {
		// Single port or range
		port := ports[0]
		if strings.Contains(port, "-") {
			// Port range
			parts := strings.Split(port, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", port)
			}
			startPort, err := strconv.ParseUint(parts[0], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", parts[0])
			}
			endPort, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", parts[1])
			}

			exprs = append(exprs, &expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: binaryPort(uint16(startPort)),
				ToData:   binaryPort(uint16(endPort)),
			})
		} else {
			// Single port
			portNum, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", port)
			}

			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryPort(uint16(portNum)),
			})
		}
	} else {
		// Multiple ports - use anonymous set
		// For simplicity, we'll use bitwise OR logic with multiple rules
		// This is a limitation - for production, consider using sets
		// For now, just match the first port and caller should add multiple rules
		portNum, err := strconv.ParseUint(ports[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", ports[0])
		}

		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryPort(uint16(portNum)),
		})
	}

	return exprs, nil
}

// binaryPort converts port to big-endian bytes (network byte order)
func binaryPort(port uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	return b
}
