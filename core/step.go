// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import "time"

// StepKind indicates the type of step.
type StepKind uint8

const (
	// StepKindCompute - internal computation step (no external I/O)
	StepKindCompute StepKind = iota
	// StepKindWriteExternal - external write (oracle/write)
	StepKindWriteExternal
	// StepKindReadExternal - external read (oracle/read)
	StepKindReadExternal
)

func (k StepKind) String() string {
	switch k {
	case StepKindCompute:
		return "compute"
	case StepKindWriteExternal:
		return "write_external"
	case StepKindReadExternal:
		return "read_external"
	default:
		return "unknown"
	}
}

// RequiresOracle returns true if this step kind requires oracle interaction.
func (k StepKind) RequiresOracle() bool {
	return k == StepKindWriteExternal || k == StepKindReadExternal
}

// StepState represents the state of a step.
type StepState uint8

const (
	StepStatePending   StepState = iota // Not yet started
	StepStateExecuting                  // Currently executing
	StepStateWaiting                    // Waiting for oracle/attestation
	StepStateCompleted                  // Successfully completed
	StepStateFailed                     // Failed
)

func (s StepState) String() string {
	switch s {
	case StepStatePending:
		return "pending"
	case StepStateExecuting:
		return "executing"
	case StepStateWaiting:
		return "waiting"
	case StepStateCompleted:
		return "completed"
	case StepStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Step represents a single execution step in a session.
type Step struct {
	// StepIndex is the step number (0-indexed)
	StepIndex uint32 `json:"stepIndex"`

	// Kind indicates the step type
	Kind StepKind `json:"kind"`

	// RequestID for external I/O steps (oracle/write or oracle/read)
	RequestID ID `json:"requestId,omitempty"`

	// RetryIndex for retry attempts
	RetryIndex uint32 `json:"retryIndex"`

	// TxID that triggered this step
	TxID ID `json:"txId"`

	// InputHash is the hash of step inputs
	InputHash ID `json:"inputHash"`

	// OutputHash is the hash of step outputs (set when completed)
	OutputHash ID `json:"outputHash,omitempty"`

	// OracleCommitRoot is the Merkle root from OracleVM (for I/O steps)
	OracleCommitRoot ID `json:"oracleCommitRoot,omitempty"`

	// AttestationID is the QuantumVM attestation over the oracle commit
	AttestationID ID `json:"attestationId,omitempty"`

	// State of this step
	State StepState `json:"state"`

	// StartedAt is when the step started
	StartedAt time.Time `json:"startedAt"`

	// CompletedAt is when the step completed
	CompletedAt time.Time `json:"completedAt,omitempty"`
}

// ComputeRequestID computes a deterministic oracle request ID.
// H("LUX:OracleRequest:v1" || service_id || session_id || step || retry || tx_id)
func ComputeRequestID(serviceID, sessionID, txID ID, step, retry uint32) ID {
	return HashMulti(
		[]byte("LUX:OracleRequest:v1"),
		serviceID[:],
		sessionID[:],
		Uint32ToBytes(step),
		Uint32ToBytes(retry),
		txID[:],
	)
}

// NewStep creates a new step.
func NewStep(index uint32, kind StepKind, txID ID, inputHash ID) *Step {
	return &Step{
		StepIndex: index,
		Kind:      kind,
		TxID:      txID,
		InputHash: inputHash,
		State:     StepStatePending,
		StartedAt: time.Now(),
	}
}

// NewOracleStep creates a new step that requires oracle interaction.
func NewOracleStep(index uint32, kind StepKind, serviceID, sessionID, txID, inputHash ID, retry uint32) *Step {
	step := NewStep(index, kind, txID, inputHash)
	step.RetryIndex = retry
	step.RequestID = ComputeRequestID(serviceID, sessionID, txID, index, retry)
	return step
}
