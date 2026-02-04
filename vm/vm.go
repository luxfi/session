// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	grjson "github.com/gorilla/rpc/v2/json"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

const (
	// Session states
	SessionPending = "pending"
	SessionActive  = "active"
	SessionExpired = "expired"
	SessionClosed  = "closed"

	// Default configuration
	defaultSessionTTL    = 24 * time.Hour
	defaultMaxMessages   = 10000
	defaultMaxChannels   = 1000
	defaultRetentionDays = 30
)

var (
	errUnknownSession = errors.New("unknown session")
	errSessionExpired = errors.New("session expired")
	errSessionClosed  = errors.New("session closed")
	errUnauthorized   = errors.New("unauthorized")
)

// Config holds SessionVM configuration
type Config struct {
	SessionTTL    int64  `json:"sessionTTL"` // Seconds
	MaxMessages   int    `json:"maxMessages"`
	MaxChannels   int    `json:"maxChannels"`
	RetentionDays int    `json:"retentionDays"`
	IDPrefix      string `json:"idPrefix"` // Post-quantum session ID prefix
}

// Session represents an encrypted communication session
type Session struct {
	ID           ids.ID            `json:"id"`
	Participants []ids.ID          `json:"participants"`
	PublicKeys   [][]byte          `json:"publicKeys"` // PQ public keys (ML-KEM)
	ChannelID    ids.ID            `json:"channelId"`
	Created      time.Time         `json:"created"`
	Expires      time.Time         `json:"expires"`
	Status       string            `json:"status"`
	Metadata     map[string]string `json:"metadata"`
}

// Message represents an encrypted message within a session
type Message struct {
	ID         ids.ID    `json:"id"`
	SessionID  ids.ID    `json:"sessionId"`
	Sender     ids.ID    `json:"sender"`
	Ciphertext []byte    `json:"ciphertext"` // Encrypted with session key
	Signature  []byte    `json:"signature"`  // ML-DSA signature
	Timestamp  time.Time `json:"timestamp"`
	Sequence   uint64    `json:"sequence"`
}

// Channel represents a multi-party communication channel
type Channel struct {
	ID           ids.ID    `json:"id"`
	Name         string    `json:"name"`
	Owner        ids.ID    `json:"owner"`
	Members      []ids.ID  `json:"members"`
	Created      time.Time `json:"created"`
	MessageCount uint64    `json:"messageCount"`
}

// VM implements the SessionVM
type VM struct {
	logger log.Logger
	config Config

	mu       sync.RWMutex
	sessions map[ids.ID]*Session
	messages map[ids.ID]*Message
	channels map[ids.ID]*Channel
	pending  []*Message
}

// Initialize initializes the VM
func (vm *VM) Initialize(logger log.Logger, configBytes []byte) error {
	vm.logger = logger
	vm.sessions = make(map[ids.ID]*Session)
	vm.messages = make(map[ids.ID]*Message)
	vm.channels = make(map[ids.ID]*Channel)
	vm.pending = make([]*Message, 0)

	// Parse config
	vm.config = Config{
		SessionTTL:    int64(defaultSessionTTL.Seconds()),
		MaxMessages:   defaultMaxMessages,
		MaxChannels:   defaultMaxChannels,
		RetentionDays: defaultRetentionDays,
		IDPrefix:      "07", // Post-quantum prefix
	}
	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	vm.logger.Info("SessionVM initialized",
		"idPrefix", vm.config.IDPrefix,
		"sessionTTL", vm.config.SessionTTL,
		"maxMessages", vm.config.MaxMessages,
	)

	return nil
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.logger.Info("SessionVM shutting down")
	return nil
}

// CreateHandlers returns the HTTP handlers for this VM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(grjson.NewCodec(), "application/json")
	server.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")

	if err := server.RegisterService(&Service{vm: vm}, Name); err != nil {
		return nil, fmt.Errorf("failed to register service: %w", err)
	}

	return map[string]http.Handler{
		"/rpc": server,
	}, nil
}

// HealthCheck returns the health status of the VM
func (vm *VM) HealthCheck(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{
		"healthy":  true,
		"sessions": len(vm.sessions),
		"channels": len(vm.channels),
	}, nil
}

// CreateSession creates a new encrypted session
func (vm *VM) CreateSession(participants []ids.ID, publicKeys [][]byte) (*Session, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Generate session ID with PQ prefix
	sessionID := vm.generateSessionID(participants)

	session := &Session{
		ID:           sessionID,
		Participants: participants,
		PublicKeys:   publicKeys,
		Created:      time.Now(),
		Expires:      time.Now().Add(time.Duration(vm.config.SessionTTL) * time.Second),
		Status:       SessionActive,
		Metadata:     make(map[string]string),
	}

	vm.sessions[sessionID] = session

	vm.logger.Info("session created", "id", sessionID, "participants", len(participants))
	return session, nil
}

// SendMessage sends an encrypted message within a session
func (vm *VM) SendMessage(sessionID ids.ID, sender ids.ID, ciphertext, signature []byte) (*Message, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	session, exists := vm.sessions[sessionID]
	if !exists {
		return nil, errUnknownSession
	}

	if session.Status != SessionActive {
		return nil, errSessionClosed
	}

	if time.Now().After(session.Expires) {
		session.Status = SessionExpired
		return nil, errSessionExpired
	}

	// Verify sender is participant
	authorized := false
	for _, p := range session.Participants {
		if p == sender {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, errUnauthorized
	}

	// Create message
	msg := &Message{
		ID:         vm.generateMessageID(sessionID, ciphertext),
		SessionID:  sessionID,
		Sender:     sender,
		Ciphertext: ciphertext,
		Signature:  signature,
		Timestamp:  time.Now(),
		Sequence:   uint64(len(vm.pending)),
	}

	vm.messages[msg.ID] = msg
	vm.pending = append(vm.pending, msg)

	return msg, nil
}

// GetSession returns a session by ID
func (vm *VM) GetSession(sessionID ids.ID) (*Session, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	session, exists := vm.sessions[sessionID]
	if !exists {
		return nil, errUnknownSession
	}
	return session, nil
}

// CloseSession closes a session
func (vm *VM) CloseSession(sessionID ids.ID) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	session, exists := vm.sessions[sessionID]
	if !exists {
		return errUnknownSession
	}

	session.Status = SessionClosed
	return nil
}

// generateSessionID generates a session ID with PQ prefix
func (vm *VM) generateSessionID(participants []ids.ID) ids.ID {
	h := sha256.New()
	h.Write([]byte(vm.config.IDPrefix))
	for _, p := range participants {
		h.Write(p[:])
	}
	h.Write([]byte(time.Now().String()))

	var id ids.ID
	copy(id[:], h.Sum(nil))
	return id
}

// generateMessageID generates a message ID
func (vm *VM) generateMessageID(sessionID ids.ID, ciphertext []byte) ids.ID {
	h := sha256.New()
	h.Write(sessionID[:])
	h.Write(ciphertext)
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())

	var id ids.ID
	copy(id[:], h.Sum(nil))
	return id
}
