// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swarm

import (
	"errors"
	"sync"
	"time"

	"github.com/luxfi/session/core"
)

// NodeStatus represents the status of a service node.
type NodeStatus uint8

const (
	NodeStatusUnknown    NodeStatus = iota
	NodeStatusRegistered            // Registered but not yet active
	NodeStatusActive                // Active and available for assignment
	NodeStatusSuspended             // Temporarily suspended
	NodeStatusExited                // Voluntarily exited
	NodeStatusSlashed               // Slashed for misbehavior
)

func (s NodeStatus) String() string {
	switch s {
	case NodeStatusRegistered:
		return "registered"
	case NodeStatusActive:
		return "active"
	case NodeStatusSuspended:
		return "suspended"
	case NodeStatusExited:
		return "exited"
	case NodeStatusSlashed:
		return "slashed"
	default:
		return "unknown"
	}
}

// ServiceNode represents a registered service node.
type ServiceNode struct {
	// ID is the node identifier
	ID core.ID `json:"id"`

	// PublicKey is the node's public key (PQ-safe)
	PublicKey []byte `json:"publicKey"`

	// Endpoint is the node's network endpoint
	Endpoint string `json:"endpoint"`

	// Status is the current node status
	Status NodeStatus `json:"status"`

	// Stake is the amount staked by this node
	Stake uint64 `json:"stake"`

	// RegisteredAt is when the node was registered
	RegisteredAt time.Time `json:"registeredAt"`

	// LastSeenAt is when the node was last seen active
	LastSeenAt time.Time `json:"lastSeenAt"`

	// Metadata contains additional node metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Registry manages service node registration and lifecycle.
type Registry struct {
	nodes      map[core.ID]*ServiceNode
	byEndpoint map[string]core.ID
	mu         sync.RWMutex
}

// NewRegistry creates a new service node registry.
func NewRegistry() *Registry {
	return &Registry{
		nodes:      make(map[core.ID]*ServiceNode),
		byEndpoint: make(map[string]core.ID),
	}
}

// Register registers a new service node.
func (r *Registry) Register(id core.ID, publicKey []byte, endpoint string, stake uint64) (*ServiceNode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.nodes[id]; exists {
		return nil, errors.New("node already registered")
	}

	if _, exists := r.byEndpoint[endpoint]; exists {
		return nil, errors.New("endpoint already registered")
	}

	node := &ServiceNode{
		ID:           id,
		PublicKey:    publicKey,
		Endpoint:     endpoint,
		Status:       NodeStatusRegistered,
		Stake:        stake,
		RegisteredAt: time.Now(),
		LastSeenAt:   time.Now(),
		Metadata:     make(map[string]string),
	}

	r.nodes[id] = node
	r.byEndpoint[endpoint] = id

	return node, nil
}

// Activate activates a registered node.
func (r *Registry) Activate(id core.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[id]
	if !ok {
		return errors.New("node not found")
	}

	if node.Status != NodeStatusRegistered && node.Status != NodeStatusSuspended {
		return errors.New("node cannot be activated from current status")
	}

	node.Status = NodeStatusActive
	node.LastSeenAt = time.Now()

	return nil
}

// Suspend suspends an active node.
func (r *Registry) Suspend(id core.ID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[id]
	if !ok {
		return errors.New("node not found")
	}

	if node.Status != NodeStatusActive {
		return errors.New("node not active")
	}

	node.Status = NodeStatusSuspended
	node.Metadata["suspend_reason"] = reason

	return nil
}

// Slash slashes a node for misbehavior.
func (r *Registry) Slash(id core.ID, evidence string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[id]
	if !ok {
		return errors.New("node not found")
	}

	node.Status = NodeStatusSlashed
	node.Metadata["slash_evidence"] = evidence

	return nil
}

// Exit marks a node as voluntarily exited.
func (r *Registry) Exit(id core.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[id]
	if !ok {
		return errors.New("node not found")
	}

	node.Status = NodeStatusExited

	return nil
}

// Get retrieves a node by ID.
func (r *Registry) Get(id core.ID) (*ServiceNode, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	node, ok := r.nodes[id]
	if !ok {
		return nil, errors.New("node not found")
	}

	return node, nil
}

// GetByEndpoint retrieves a node by endpoint.
func (r *Registry) GetByEndpoint(endpoint string) (*ServiceNode, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.byEndpoint[endpoint]
	if !ok {
		return nil, errors.New("endpoint not found")
	}

	return r.nodes[id], nil
}

// GetActive returns all active nodes.
func (r *Registry) GetActive() []*ServiceNode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var active []*ServiceNode
	for _, node := range r.nodes {
		if node.Status == NodeStatusActive {
			active = append(active, node)
		}
	}

	return active
}

// GetActiveIDs returns IDs of all active nodes.
func (r *Registry) GetActiveIDs() []core.ID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var ids []core.ID
	for _, node := range r.nodes {
		if node.Status == NodeStatusActive {
			ids = append(ids, node.ID)
		}
	}

	return ids
}

// UpdateHeartbeat updates a node's last seen time.
func (r *Registry) UpdateHeartbeat(id core.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[id]
	if !ok {
		return errors.New("node not found")
	}

	node.LastSeenAt = time.Now()

	return nil
}

// Count returns the total number of nodes.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nodes)
}

// CountActive returns the number of active nodes.
func (r *Registry) CountActive() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, node := range r.nodes {
		if node.Status == NodeStatusActive {
			count++
		}
	}
	return count
}
