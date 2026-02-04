// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import "time"

// SessionState represents the state of a session.
type SessionState uint8

const (
	// SessionStatePending - session created but not started
	SessionStatePending SessionState = iota
	// SessionStateRunning - session actively executing
	SessionStateRunning
	// SessionStateWaitingIO - session waiting for external I/O completion
	SessionStateWaitingIO
	// SessionStateFinalized - session completed successfully
	SessionStateFinalized
	// SessionStateFailed - session failed
	SessionStateFailed
)

func (s SessionState) String() string {
	switch s {
	case SessionStatePending:
		return "pending"
	case SessionStateRunning:
		return "running"
	case SessionStateWaitingIO:
		return "waiting_io"
	case SessionStateFinalized:
		return "finalized"
	case SessionStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Session represents a private permissionless session.
// This is the canonical session type shared by on-chain and off-chain code.
type Session struct {
	// ID is the unique session identifier: H("LUX:Session:v1" || service_id || epoch || tx_id)
	ID ID `json:"id"`

	// ServiceID identifies the service being executed
	ServiceID ID `json:"serviceId"`

	// Epoch in which this session was created
	Epoch uint64 `json:"epoch"`

	// TxID is the transaction that created this session
	TxID ID `json:"txId"`

	// Committee assigned to execute this session (node IDs)
	Committee []ID `json:"committee"`

	// State is the current session state
	State SessionState `json:"state"`

	// CurrentStep is the current step index
	CurrentStep uint32 `json:"currentStep"`

	// Steps are the step records for this session
	Steps []*Step `json:"steps"`

	// OutputHash is the final output hash (set when finalized)
	OutputHash ID `json:"outputHash,omitempty"`

	// OracleRoot is the Merkle root of all oracle observations
	OracleRoot ID `json:"oracleRoot,omitempty"`

	// ReceiptsRoot is the Merkle root of all relay receipts
	ReceiptsRoot ID `json:"receiptsRoot,omitempty"`

	// CreatedAt is when the session was created
	CreatedAt time.Time `json:"createdAt"`

	// FinalizedAt is when the session was finalized (if applicable)
	FinalizedAt time.Time `json:"finalizedAt,omitempty"`

	// Error message if session failed
	Error string `json:"error,omitempty"`
}

// ComputeSessionID computes a deterministic session ID.
// H("LUX:Session:v1" || service_id || epoch || tx_id)
func ComputeSessionID(serviceID ID, epoch uint64, txID ID) ID {
	return HashMulti(
		[]byte("LUX:Session:v1"),
		serviceID[:],
		Uint64ToBytes(epoch),
		txID[:],
	)
}

// NewSession creates a new session in the pending state.
func NewSession(serviceID ID, epoch uint64, txID ID, committee []ID) *Session {
	return &Session{
		ID:        ComputeSessionID(serviceID, epoch, txID),
		ServiceID: serviceID,
		Epoch:     epoch,
		TxID:      txID,
		Committee: committee,
		State:     SessionStatePending,
		Steps:     []*Step{},
		CreatedAt: time.Now(),
	}
}
