// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package protocol

import (
	"time"

	"github.com/luxfi/session/core"
)

// RequestKind indicates the type of oracle request.
type RequestKind uint8

const (
	// RequestKindWrite - external write request
	RequestKindWrite RequestKind = iota
	// RequestKindRead - external read request
	RequestKindRead
)

func (k RequestKind) String() string {
	switch k {
	case RequestKindWrite:
		return "write"
	case RequestKindRead:
		return "read"
	default:
		return "unknown"
	}
}

// RequestStatus indicates the status of an oracle request.
type RequestStatus uint8

const (
	RequestStatusPending   RequestStatus = iota // Waiting for records
	RequestStatusCommitted                      // Records committed
	RequestStatusAttested                       // Attestation received
)

func (s RequestStatus) String() string {
	switch s {
	case RequestStatusPending:
		return "pending"
	case RequestStatusCommitted:
		return "committed"
	case RequestStatusAttested:
		return "attested"
	default:
		return "unknown"
	}
}

// OracleRequest represents a request for external I/O.
type OracleRequest struct {
	// ID is the deterministic request identifier
	// H("LUX:OracleRequest:v1" || service_id || session_id || step || retry || tx_id)
	ID core.ID `json:"id"`

	// ServiceID identifies the service
	ServiceID core.ID `json:"serviceId"`

	// SessionID identifies the session
	SessionID core.ID `json:"sessionId"`

	// StepIndex is the step number
	StepIndex uint32 `json:"stepIndex"`

	// RetryIndex for retry attempts
	RetryIndex uint32 `json:"retryIndex"`

	// TxID that triggered this request
	TxID core.ID `json:"txId"`

	// Kind of request (read or write)
	Kind RequestKind `json:"kind"`

	// Status of the request
	Status RequestStatus `json:"status"`

	// InputHash is the hash of request inputs
	InputHash core.ID `json:"inputHash"`

	// Records collected for this request
	Records []*OracleRecord `json:"records,omitempty"`

	// CommitRoot is the Merkle root of committed records
	CommitRoot core.ID `json:"commitRoot,omitempty"`

	// AttestationID is the attestation over the commit
	AttestationID core.ID `json:"attestationId,omitempty"`

	// CreatedAt is when the request was created
	CreatedAt time.Time `json:"createdAt"`

	// CommittedAt is when records were committed
	CommittedAt time.Time `json:"committedAt,omitempty"`
}

// OracleRecord represents a single oracle observation.
type OracleRecord struct {
	// RecordID is the unique record identifier
	RecordID core.ID `json:"recordId"`

	// RequestID this record belongs to
	RequestID core.ID `json:"requestId"`

	// SubmitterID is the node that submitted this record
	SubmitterID core.ID `json:"submitterId"`

	// Data is the record payload
	Data []byte `json:"data"`

	// DataHash is the hash of the data
	DataHash core.ID `json:"dataHash"`

	// Signature from the submitter
	Signature []byte `json:"signature"`

	// CreatedAt is when the record was created
	CreatedAt time.Time `json:"createdAt"`
}

// OracleCommit represents a committed set of oracle records.
type OracleCommit struct {
	// RequestID this commit is for
	RequestID core.ID `json:"requestId"`

	// MerkleRoot of all records
	MerkleRoot core.ID `json:"merkleRoot"`

	// RecordCount is the number of records
	RecordCount uint32 `json:"recordCount"`

	// Epoch when committed
	Epoch uint64 `json:"epoch"`

	// CommittedAt is when the commit was created
	CommittedAt time.Time `json:"committedAt"`
}

// NewOracleRequest creates a new oracle request.
func NewOracleRequest(serviceID, sessionID, txID, inputHash core.ID, step, retry uint32, kind RequestKind) *OracleRequest {
	return &OracleRequest{
		ID:         core.ComputeRequestID(serviceID, sessionID, txID, step, retry),
		ServiceID:  serviceID,
		SessionID:  sessionID,
		StepIndex:  step,
		RetryIndex: retry,
		TxID:       txID,
		Kind:       kind,
		Status:     RequestStatusPending,
		InputHash:  inputHash,
		Records:    []*OracleRecord{},
		CreatedAt:  time.Now(),
	}
}

// NewOracleRecord creates a new oracle record.
func NewOracleRecord(requestID, submitterID core.ID, data []byte, signature []byte) *OracleRecord {
	dataHash := core.Hash(data)
	return &OracleRecord{
		RecordID:    core.HashMulti(requestID[:], submitterID[:], dataHash[:]),
		RequestID:   requestID,
		SubmitterID: submitterID,
		Data:        data,
		DataHash:    dataHash,
		Signature:   signature,
		CreatedAt:   time.Now(),
	}
}

// ComputeMerkleRoot computes the Merkle root of a set of records.
// Uses a simple binary Merkle tree construction.
func ComputeMerkleRoot(records []*OracleRecord) core.ID {
	if len(records) == 0 {
		return core.ID{}
	}

	// Get leaf hashes
	leaves := make([]core.ID, len(records))
	for i, r := range records {
		leaves[i] = r.DataHash
	}

	// Build tree bottom-up
	for len(leaves) > 1 {
		var nextLevel []core.ID
		for i := 0; i < len(leaves); i += 2 {
			if i+1 < len(leaves) {
				nextLevel = append(nextLevel, core.HashMulti(leaves[i][:], leaves[i+1][:]))
			} else {
				nextLevel = append(nextLevel, leaves[i])
			}
		}
		leaves = nextLevel
	}

	return leaves[0]
}

// MerkleProof represents a Merkle inclusion proof.
type MerkleProof struct {
	// LeafIndex is the index of the leaf
	LeafIndex uint32 `json:"leafIndex"`

	// Siblings are the sibling hashes along the path
	Siblings []core.ID `json:"siblings"`

	// IsLeft indicates if the sibling is on the left at each level
	IsLeft []bool `json:"isLeft"`
}

// VerifyMerkleProof verifies a Merkle inclusion proof.
func VerifyMerkleProof(root, leaf core.ID, proof *MerkleProof) bool {
	current := leaf
	for i, sibling := range proof.Siblings {
		if proof.IsLeft[i] {
			current = core.HashMulti(sibling[:], current[:])
		} else {
			current = core.HashMulti(current[:], sibling[:])
		}
	}
	return current == root
}
