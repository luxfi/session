// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package daemon implements the sessiond service node daemon.
// This is the off-chain component that runs session workloads.
package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/session/core"
	"github.com/luxfi/session/network"
	"github.com/luxfi/session/protocol"
	"github.com/luxfi/session/storage"
	"github.com/luxfi/session/swarm"
)

// Config holds the daemon configuration.
type Config struct {
	// NodeID is this node's identifier
	NodeID core.ID

	// ListenAddr is the address to listen on
	ListenAddr string

	// BootstrapPeers are initial peers to connect to
	BootstrapPeers []string

	// DataDir is the directory for persistent data
	DataDir string

	// MaxSessions is the maximum concurrent sessions
	MaxSessions int

	// SessionTimeout is the timeout for session execution
	SessionTimeout time.Duration

	// HeartbeatInterval is the interval between heartbeats
	HeartbeatInterval time.Duration
}

// DefaultConfig returns the default daemon configuration.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:        ":9651",
		MaxSessions:       100,
		SessionTimeout:    5 * time.Minute,
		HeartbeatInterval: 30 * time.Second,
	}
}

// Service is the main sessiond service.
type Service struct {
	config *Config

	// Core components
	transport network.Transport
	store     storage.Store
	registry  *swarm.Registry
	assigner  *swarm.Assigner
	router    *network.Router

	// Session management
	sessions    map[core.ID]*SessionRunner
	sessionsMu  sync.RWMutex
	maxSessions int
	activeSem   chan struct{}

	// Oracle request tracking
	pendingRequests   map[core.ID]*protocol.OracleRequest
	pendingRequestsMu sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new sessiond service.
func New(config *Config) *Service {
	if config == nil {
		config = DefaultConfig()
	}

	return &Service{
		config:          config,
		registry:        swarm.NewRegistry(),
		assigner:        swarm.NewAssigner(nil),
		router:          network.NewRouter(),
		sessions:        make(map[core.ID]*SessionRunner),
		pendingRequests: make(map[core.ID]*protocol.OracleRequest),
		maxSessions:     config.MaxSessions,
		activeSem:       make(chan struct{}, config.MaxSessions),
	}
}

// Start starts the service.
func (s *Service) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Initialize storage
	s.store = storage.NewMemoryStore()

	// Register message handlers
	s.registerHandlers()

	// Start background tasks
	s.wg.Add(1)
	go s.heartbeatLoop()

	return nil
}

// Stop stops the service.
func (s *Service) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}

	// Stop all active sessions
	s.sessionsMu.Lock()
	for _, runner := range s.sessions {
		runner.Stop()
	}
	s.sessionsMu.Unlock()

	// Wait for background tasks
	s.wg.Wait()

	// Close storage
	if s.store != nil {
		s.store.Close()
	}

	return nil
}

// registerHandlers registers message handlers.
func (s *Service) registerHandlers() {
	s.router.RegisterFunc(network.MessageTypeSessionCreate, s.handleSessionCreate)
	s.router.RegisterFunc(network.MessageTypeSessionStart, s.handleSessionStart)
	s.router.RegisterFunc(network.MessageTypeOracleRequest, s.handleOracleRequest)
	s.router.RegisterFunc(network.MessageTypeOracleRecord, s.handleOracleRecord)
	s.router.RegisterFunc(network.MessageTypeOracleCommit, s.handleOracleCommit)
	s.router.RegisterFunc(network.MessageTypeAttestation, s.handleAttestation)
	s.router.RegisterFunc(network.MessageTypePing, s.handlePing)
}

// SessionCreateRequest is the payload for session creation.
type SessionCreateRequest struct {
	ServiceID core.ID
	Epoch     uint64
	TxID      core.ID
	Committee []core.ID
}

// DecodeSessionCreateRequest decodes a session create request from bytes.
func DecodeSessionCreateRequest(data []byte) (*SessionCreateRequest, error) {
	if len(data) < 32+8+32+4 {
		return nil, errors.New("data too short")
	}

	req := &SessionCreateRequest{}
	offset := 0

	copy(req.ServiceID[:], data[offset:])
	offset += 32

	req.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(req.TxID[:], data[offset:])
	offset += 32

	committeeLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	req.Committee = make([]core.ID, committeeLen)
	for i := uint32(0); i < committeeLen; i++ {
		if offset+32 > len(data) {
			return nil, errors.New("data too short for committee")
		}
		copy(req.Committee[i][:], data[offset:])
		offset += 32
	}

	return req, nil
}

// EncodeSessionCreateRequest encodes a session create request to bytes.
func EncodeSessionCreateRequest(req *SessionCreateRequest) []byte {
	size := 32 + 8 + 32 + 4 + len(req.Committee)*32
	data := make([]byte, size)
	offset := 0

	copy(data[offset:], req.ServiceID[:])
	offset += 32

	binary.BigEndian.PutUint64(data[offset:], req.Epoch)
	offset += 8

	copy(data[offset:], req.TxID[:])
	offset += 32

	binary.BigEndian.PutUint32(data[offset:], uint32(len(req.Committee)))
	offset += 4

	for _, id := range req.Committee {
		copy(data[offset:], id[:])
		offset += 32
	}

	return data
}

// handleSessionCreate handles session creation requests.
func (s *Service) handleSessionCreate(ctx context.Context, msg *network.Message) (*network.Message, error) {
	req, err := DecodeSessionCreateRequest(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode session create request: %w", err)
	}

	session, err := s.CreateSession(req.ServiceID, req.Epoch, req.TxID, req.Committee)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Return session ID in response
	return &network.Message{
		Type:      network.MessageTypeSessionCreate,
		From:      s.config.NodeID,
		To:        msg.From,
		Payload:   session.ID[:],
		Timestamp: time.Now(),
	}, nil
}

// handleSessionStart handles session start requests.
func (s *Service) handleSessionStart(ctx context.Context, msg *network.Message) (*network.Message, error) {
	if len(msg.Payload) < 32 {
		return nil, errors.New("invalid session ID")
	}

	var sessionID core.ID
	copy(sessionID[:], msg.Payload)

	err := s.StartSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("start session: %w", err)
	}

	// Return acknowledgment
	return &network.Message{
		Type:      network.MessageTypeSessionStart,
		From:      s.config.NodeID,
		To:        msg.From,
		Payload:   []byte{1}, // Success
		Timestamp: time.Now(),
	}, nil
}

// OracleRequestMessage is the payload for oracle request messages.
type OracleRequestMessage struct {
	SessionID core.ID
	StepKind  core.StepKind
	TxID      core.ID
	InputHash core.ID
}

// DecodeOracleRequestMessage decodes an oracle request message.
func DecodeOracleRequestMessage(data []byte) (*OracleRequestMessage, error) {
	if len(data) < 32+1+32+32 {
		return nil, errors.New("data too short")
	}

	msg := &OracleRequestMessage{}
	offset := 0

	copy(msg.SessionID[:], data[offset:])
	offset += 32

	msg.StepKind = core.StepKind(data[offset])
	offset++

	copy(msg.TxID[:], data[offset:])
	offset += 32

	copy(msg.InputHash[:], data[offset:])

	return msg, nil
}

// handleOracleRequest handles oracle request messages.
func (s *Service) handleOracleRequest(ctx context.Context, msg *network.Message) (*network.Message, error) {
	reqMsg, err := DecodeOracleRequestMessage(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode oracle request: %w", err)
	}

	s.sessionsMu.RLock()
	runner, ok := s.sessions[reqMsg.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	oracleReq, err := runner.CreateOracleRequest(reqMsg.StepKind, reqMsg.TxID, reqMsg.InputHash)
	if err != nil {
		return nil, fmt.Errorf("create oracle request: %w", err)
	}

	// Track pending request
	s.pendingRequestsMu.Lock()
	s.pendingRequests[oracleReq.ID] = oracleReq
	s.pendingRequestsMu.Unlock()

	// Return request ID
	return &network.Message{
		Type:      network.MessageTypeOracleRequest,
		From:      s.config.NodeID,
		To:        msg.From,
		Payload:   oracleReq.ID[:],
		Timestamp: time.Now(),
	}, nil
}

// OracleRecordMessage is the payload for oracle record submissions.
type OracleRecordMessage struct {
	RequestID   core.ID
	SubmitterID core.ID
	Data        []byte
	Signature   []byte
}

// DecodeOracleRecordMessage decodes an oracle record message.
func DecodeOracleRecordMessage(data []byte) (*OracleRecordMessage, error) {
	if len(data) < 32+32+4 {
		return nil, errors.New("data too short")
	}

	msg := &OracleRecordMessage{}
	offset := 0

	copy(msg.RequestID[:], data[offset:])
	offset += 32

	copy(msg.SubmitterID[:], data[offset:])
	offset += 32

	dataLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if offset+int(dataLen)+4 > len(data) {
		return nil, errors.New("data too short for record data")
	}

	msg.Data = make([]byte, dataLen)
	copy(msg.Data, data[offset:])
	offset += int(dataLen)

	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if sigLen > 0 && offset+int(sigLen) <= len(data) {
		msg.Signature = make([]byte, sigLen)
		copy(msg.Signature, data[offset:])
	}

	return msg, nil
}

// handleOracleRecord handles oracle record submissions.
func (s *Service) handleOracleRecord(ctx context.Context, msg *network.Message) (*network.Message, error) {
	recMsg, err := DecodeOracleRecordMessage(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode oracle record: %w", err)
	}

	s.pendingRequestsMu.Lock()
	oracleReq, ok := s.pendingRequests[recMsg.RequestID]
	if !ok {
		s.pendingRequestsMu.Unlock()
		return nil, errors.New("oracle request not found")
	}

	record := protocol.NewOracleRecord(recMsg.RequestID, recMsg.SubmitterID, recMsg.Data, recMsg.Signature)
	oracleReq.Records = append(oracleReq.Records, record)
	s.pendingRequestsMu.Unlock()

	// Return record ID
	return &network.Message{
		Type:      network.MessageTypeOracleRecord,
		From:      s.config.NodeID,
		To:        msg.From,
		Payload:   record.RecordID[:],
		Timestamp: time.Now(),
	}, nil
}

// OracleCommitMessage is the payload for oracle commit messages.
type OracleCommitMessage struct {
	RequestID core.ID
}

// handleOracleCommit handles oracle commit messages.
func (s *Service) handleOracleCommit(ctx context.Context, msg *network.Message) (*network.Message, error) {
	if len(msg.Payload) < 32 {
		return nil, errors.New("invalid request ID")
	}

	var requestID core.ID
	copy(requestID[:], msg.Payload)

	s.pendingRequestsMu.Lock()
	oracleReq, ok := s.pendingRequests[requestID]
	if !ok {
		s.pendingRequestsMu.Unlock()
		return nil, errors.New("oracle request not found")
	}

	// Compute Merkle root
	commitRoot := protocol.ComputeMerkleRoot(oracleReq.Records)
	oracleReq.CommitRoot = commitRoot
	oracleReq.Status = protocol.RequestStatusCommitted
	oracleReq.CommittedAt = time.Now()
	s.pendingRequestsMu.Unlock()

	// Return commit root
	return &network.Message{
		Type:      network.MessageTypeOracleCommit,
		From:      s.config.NodeID,
		To:        msg.From,
		Payload:   commitRoot[:],
		Timestamp: time.Now(),
	}, nil
}

// AttestationMessage is the payload for attestation messages.
type AttestationMessage struct {
	SessionID     core.ID
	StepIndex     uint32
	CommitRoot    core.ID
	AttestationID core.ID
	OutputHash    core.ID
}

// DecodeAttestationMessage decodes an attestation message.
func DecodeAttestationMessage(data []byte) (*AttestationMessage, error) {
	if len(data) < 32+4+32+32+32 {
		return nil, errors.New("data too short")
	}

	msg := &AttestationMessage{}
	offset := 0

	copy(msg.SessionID[:], data[offset:])
	offset += 32

	msg.StepIndex = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	copy(msg.CommitRoot[:], data[offset:])
	offset += 32

	copy(msg.AttestationID[:], data[offset:])
	offset += 32

	copy(msg.OutputHash[:], data[offset:])

	return msg, nil
}

// handleAttestation handles attestation messages.
func (s *Service) handleAttestation(ctx context.Context, msg *network.Message) (*network.Message, error) {
	attMsg, err := DecodeAttestationMessage(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode attestation: %w", err)
	}

	s.sessionsMu.RLock()
	runner, ok := s.sessions[attMsg.SessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	err = runner.CompleteStep(attMsg.StepIndex, attMsg.CommitRoot, attMsg.AttestationID, attMsg.OutputHash)
	if err != nil {
		return nil, fmt.Errorf("complete step: %w", err)
	}

	// Return acknowledgment
	return &network.Message{
		Type:      network.MessageTypeAttestation,
		From:      s.config.NodeID,
		To:        msg.From,
		Payload:   []byte{1}, // Success
		Timestamp: time.Now(),
	}, nil
}

// handlePing handles ping messages.
func (s *Service) handlePing(ctx context.Context, msg *network.Message) (*network.Message, error) {
	return &network.Message{
		Type:      network.MessageTypePong,
		From:      s.config.NodeID,
		To:        msg.From,
		Timestamp: time.Now(),
	}, nil
}

// heartbeatLoop sends periodic heartbeats.
func (s *Service) heartbeatLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.registry.UpdateHeartbeat(s.config.NodeID)
		}
	}
}

// CreateSession creates a new session.
func (s *Service) CreateSession(serviceID core.ID, epoch uint64, txID core.ID, committee []core.ID) (*core.Session, error) {
	// Check capacity
	select {
	case s.activeSem <- struct{}{}:
		// Got slot
	default:
		return nil, errors.New("maximum sessions reached")
	}

	session := core.NewSession(serviceID, epoch, txID, committee)

	s.sessionsMu.Lock()
	runner := NewSessionRunner(s, session)
	s.sessions[session.ID] = runner
	s.sessionsMu.Unlock()

	return session, nil
}

// GetSession retrieves a session by ID.
func (s *Service) GetSession(sessionID core.ID) (*core.Session, error) {
	s.sessionsMu.RLock()
	runner, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	return runner.session, nil
}

// StartSession starts a session.
func (s *Service) StartSession(sessionID core.ID) error {
	s.sessionsMu.RLock()
	runner, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return errors.New("session not found")
	}

	return runner.Start(s.ctx)
}

// FinalizeSession finalizes a session.
func (s *Service) FinalizeSession(sessionID, outputHash, oracleRoot, receiptsRoot core.ID) error {
	s.sessionsMu.RLock()
	runner, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		return errors.New("session not found")
	}

	return runner.Finalize(outputHash, oracleRoot, receiptsRoot)
}

// SessionRunner manages the execution of a single session.
type SessionRunner struct {
	service *Service
	session *core.Session

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
}

// NewSessionRunner creates a new session runner.
func NewSessionRunner(service *Service, session *core.Session) *SessionRunner {
	return &SessionRunner{
		service: service,
		session: session,
	}
}

// Start starts the session execution.
func (r *SessionRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.session.State != core.SessionStatePending {
		return errors.New("session not in pending state")
	}

	r.ctx, r.cancel = context.WithCancel(ctx)
	r.session.State = core.SessionStateRunning

	// Start execution in background
	go r.run()

	return nil
}

// Stop stops the session execution.
func (r *SessionRunner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
	}
}

// run executes the session.
func (r *SessionRunner) run() {
	defer func() {
		// Release session slot
		<-r.service.activeSem
	}()

	// Session execution loop
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
			r.mu.Lock()
			state := r.session.State
			r.mu.Unlock()

			if state == core.SessionStateFinalized || state == core.SessionStateFailed {
				return
			}

			// Sleep briefly between iterations
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// CreateOracleRequest creates an oracle request for the session.
func (r *SessionRunner) CreateOracleRequest(kind core.StepKind, txID, inputHash core.ID) (*protocol.OracleRequest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.session.State != core.SessionStateRunning {
		return nil, errors.New("session not running")
	}

	stepIndex := uint32(len(r.session.Steps))
	retryIndex := uint32(0)

	// Create oracle request
	reqKind := protocol.RequestKindWrite
	if kind == core.StepKindReadExternal {
		reqKind = protocol.RequestKindRead
	}

	request := protocol.NewOracleRequest(
		r.session.ServiceID,
		r.session.ID,
		txID,
		inputHash,
		stepIndex,
		retryIndex,
		reqKind,
	)

	// Create step
	step := core.NewOracleStep(
		stepIndex,
		kind,
		r.session.ServiceID,
		r.session.ID,
		txID,
		inputHash,
		retryIndex,
	)

	r.session.Steps = append(r.session.Steps, step)
	r.session.CurrentStep = stepIndex
	r.session.State = core.SessionStateWaitingIO

	return request, nil
}

// CompleteStep completes a step with attestation.
func (r *SessionRunner) CompleteStep(stepIndex uint32, oracleCommitRoot, attestationID, outputHash core.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if int(stepIndex) >= len(r.session.Steps) {
		return errors.New("step index out of range")
	}

	step := r.session.Steps[stepIndex]
	step.OracleCommitRoot = oracleCommitRoot
	step.AttestationID = attestationID
	step.OutputHash = outputHash
	step.State = core.StepStateCompleted
	step.CompletedAt = time.Now()

	r.session.State = core.SessionStateRunning

	return nil
}

// Finalize finalizes the session.
func (r *SessionRunner) Finalize(outputHash, oracleRoot, receiptsRoot core.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.session.State != core.SessionStateRunning {
		return errors.New("session not running")
	}

	// Verify all steps completed
	for i, step := range r.session.Steps {
		if step.State != core.StepStateCompleted {
			return fmt.Errorf("step %d not completed", i)
		}
	}

	r.session.OutputHash = outputHash
	r.session.OracleRoot = oracleRoot
	r.session.ReceiptsRoot = receiptsRoot
	r.session.State = core.SessionStateFinalized
	r.session.FinalizedAt = time.Now()

	return nil
}

// Session returns the underlying session.
func (r *SessionRunner) Session() *core.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.session
}
