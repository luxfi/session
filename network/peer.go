// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package network

import (
	"sync"
	"time"

	"github.com/luxfi/session/core"
)

// PeerState represents the state of a peer connection.
type PeerState uint8

const (
	PeerStateDisconnected PeerState = iota
	PeerStateConnecting
	PeerStateConnected
	PeerStateDisconnecting
)

func (s PeerState) String() string {
	switch s {
	case PeerStateDisconnected:
		return "disconnected"
	case PeerStateConnecting:
		return "connecting"
	case PeerStateConnected:
		return "connected"
	case PeerStateDisconnecting:
		return "disconnecting"
	default:
		return "unknown"
	}
}

// Peer represents a network peer.
type Peer struct {
	// ID is the peer's node ID
	ID core.ID `json:"id"`

	// Addr is the peer's network address
	Addr string `json:"addr"`

	// State is the connection state
	State PeerState `json:"state"`

	// PublicKey is the peer's public key (PQ-safe)
	PublicKey []byte `json:"publicKey,omitempty"`

	// LastSeen is when the peer was last seen
	LastSeen time.Time `json:"lastSeen"`

	// ConnectedAt is when the connection was established
	ConnectedAt time.Time `json:"connectedAt,omitempty"`

	// MessagesSent is the count of messages sent to this peer
	MessagesSent uint64 `json:"messagesSent"`

	// MessagesReceived is the count of messages received from this peer
	MessagesReceived uint64 `json:"messagesReceived"`

	// Latency is the measured round-trip latency
	Latency time.Duration `json:"latency"`

	// conn is the underlying connection
	conn Connection

	mu sync.RWMutex
}

// NewPeer creates a new peer.
func NewPeer(id core.ID, addr string) *Peer {
	return &Peer{
		ID:       id,
		Addr:     addr,
		State:    PeerStateDisconnected,
		LastSeen: time.Now(),
	}
}

// SetConnection sets the peer's connection.
func (p *Peer) SetConnection(conn Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conn = conn
	p.State = PeerStateConnected
	p.ConnectedAt = time.Now()
	p.LastSeen = time.Now()
}

// Connection returns the peer's connection.
func (p *Peer) Connection() Connection {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.conn
}

// Disconnect disconnects the peer.
func (p *Peer) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conn != nil {
		err := p.conn.Close()
		p.conn = nil
		p.State = PeerStateDisconnected
		return err
	}
	p.State = PeerStateDisconnected
	return nil
}

// UpdateLatency updates the peer's latency measurement.
func (p *Peer) UpdateLatency(latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Exponential moving average
	if p.Latency == 0 {
		p.Latency = latency
	} else {
		p.Latency = (p.Latency*7 + latency) / 8
	}
}

// IncrementSent increments the sent message counter.
func (p *Peer) IncrementSent() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.MessagesSent++
	p.LastSeen = time.Now()
}

// IncrementReceived increments the received message counter.
func (p *Peer) IncrementReceived() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.MessagesReceived++
	p.LastSeen = time.Now()
}

// PeerManager manages the set of peers.
type PeerManager struct {
	peers    map[core.ID]*Peer
	byAddr   map[string]core.ID
	maxPeers int
	mu       sync.RWMutex
}

// NewPeerManager creates a new peer manager.
func NewPeerManager(maxPeers int) *PeerManager {
	return &PeerManager{
		peers:    make(map[core.ID]*Peer),
		byAddr:   make(map[string]core.ID),
		maxPeers: maxPeers,
	}
}

// Add adds a peer.
func (pm *PeerManager) Add(peer *Peer) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.peers) >= pm.maxPeers {
		return ErrMaxPeersReached
	}

	pm.peers[peer.ID] = peer
	pm.byAddr[peer.Addr] = peer.ID

	return nil
}

// Remove removes a peer.
func (pm *PeerManager) Remove(id core.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if peer, ok := pm.peers[id]; ok {
		delete(pm.byAddr, peer.Addr)
		delete(pm.peers, id)
	}
}

// Get gets a peer by ID.
func (pm *PeerManager) Get(id core.ID) (*Peer, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	peer, ok := pm.peers[id]
	return peer, ok
}

// GetByAddr gets a peer by address.
func (pm *PeerManager) GetByAddr(addr string) (*Peer, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	id, ok := pm.byAddr[addr]
	if !ok {
		return nil, false
	}
	return pm.peers[id], true
}

// All returns all peers.
func (pm *PeerManager) All() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, p := range pm.peers {
		peers = append(peers, p)
	}
	return peers
}

// Connected returns all connected peers.
func (pm *PeerManager) Connected() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var connected []*Peer
	for _, p := range pm.peers {
		if p.State == PeerStateConnected {
			connected = append(connected, p)
		}
	}
	return connected
}

// ConnectedIDs returns IDs of all connected peers.
func (pm *PeerManager) ConnectedIDs() []core.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var ids []core.ID
	for _, p := range pm.peers {
		if p.State == PeerStateConnected {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

// Count returns the total number of peers.
func (pm *PeerManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.peers)
}

// CountConnected returns the number of connected peers.
func (pm *PeerManager) CountConnected() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	count := 0
	for _, p := range pm.peers {
		if p.State == PeerStateConnected {
			count++
		}
	}
	return count
}

// ErrMaxPeersReached is returned when the maximum number of peers is reached.
var ErrMaxPeersReached = Error("maximum peers reached")

// Error is a network error type.
type Error string

func (e Error) Error() string { return string(e) }
