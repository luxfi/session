// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package protocol

import (
	"errors"
	"time"

	"github.com/luxfi/session/core"
)

// Attestation represents a threshold attestation from the QuantumVM committee.
// Attestations are the cryptographic proof that a quorum of nodes agree on a statement.
type Attestation struct {
	// ID is the unique attestation identifier
	ID core.ID `json:"id"`

	// Domain specifies what is being attested
	Domain Domain `json:"domain"`

	// SubjectID is what is being attested (request_id, session_id, or epoch)
	SubjectID core.ID `json:"subjectId"`

	// CommitRoot is the Merkle root being attested
	CommitRoot core.ID `json:"commitRoot"`

	// Epoch when attestation was created
	Epoch uint64 `json:"epoch"`

	// Signers are the node IDs that signed this attestation
	Signers []core.ID `json:"signers"`

	// Signature is the aggregated threshold signature
	Signature []byte `json:"signature"`

	// CreatedAt is when the attestation was created
	CreatedAt time.Time `json:"createdAt"`
}

// ComputeAttestationID computes a deterministic attestation ID.
func ComputeAttestationID(domain Domain, subjectID, commitRoot core.ID, epoch uint64) core.ID {
	return core.HashMulti(
		DomainSeparator(domain),
		subjectID[:],
		commitRoot[:],
		core.Uint64ToBytes(epoch),
	)
}

// NewAttestation creates a new attestation.
func NewAttestation(domain Domain, subjectID, commitRoot core.ID, epoch uint64, signers []core.ID, signature []byte) *Attestation {
	return &Attestation{
		ID:         ComputeAttestationID(domain, subjectID, commitRoot, epoch),
		Domain:     domain,
		SubjectID:  subjectID,
		CommitRoot: commitRoot,
		Epoch:      epoch,
		Signers:    signers,
		Signature:  signature,
		CreatedAt:  time.Now(),
	}
}

// SigningPayload returns the payload that should be signed for this attestation.
func (a *Attestation) SigningPayload() []byte {
	return append(
		append(
			append(DomainSeparator(a.Domain), a.SubjectID[:]...),
			a.CommitRoot[:]...,
		),
		core.Uint64ToBytes(a.Epoch)...,
	)
}

// OracleCommitAttestation is an attestation over an oracle commit.
type OracleCommitAttestation struct {
	*Attestation
	RequestID core.ID `json:"requestId"`
}

// SessionCompleteAttestation is an attestation over session completion.
type SessionCompleteAttestation struct {
	*Attestation
	SessionID    core.ID `json:"sessionId"`
	OutputHash   core.ID `json:"outputHash"`
	OracleRoot   core.ID `json:"oracleRoot"`
	ReceiptsRoot core.ID `json:"receiptsRoot"`
}

// EpochBeaconAttestation is an attestation over epoch randomness.
type EpochBeaconAttestation struct {
	*Attestation
	Randomness core.ID `json:"randomness"`
}

// ValidateAttestationForStep validates that an attestation is valid for completing a step.
func ValidateAttestationForStep(step *core.Step, attestation *Attestation) error {
	// Verify domain matches step kind
	expectedDomain := DomainForStepKind(step.Kind)
	if expectedDomain == "" {
		return errors.New("step kind does not require attestation")
	}
	if attestation.Domain != expectedDomain {
		return errors.New("attestation domain does not match step kind")
	}

	// Verify subject ID matches request ID
	if attestation.SubjectID != step.RequestID {
		return errors.New("attestation subject ID does not match request ID")
	}

	return nil
}

// EquivocationEvidence represents evidence of a node signing conflicting attestations.
type EquivocationEvidence struct {
	// NodeID of the equivocating node
	NodeID core.ID `json:"nodeId"`

	// First attestation
	First *Attestation `json:"first"`

	// Second conflicting attestation
	Second *Attestation `json:"second"`

	// DetectedAt is when the equivocation was detected
	DetectedAt time.Time `json:"detectedAt"`
}

// DetectEquivocation checks if two attestations represent equivocation by the same signer.
// Returns evidence if equivocation is detected.
func DetectEquivocation(a1, a2 *Attestation) *EquivocationEvidence {
	// Same domain and subject but different commit roots = equivocation
	if a1.Domain != a2.Domain || a1.SubjectID != a2.SubjectID {
		return nil
	}
	if a1.CommitRoot == a2.CommitRoot {
		return nil
	}

	// Find common signers
	signerSet := make(map[core.ID]bool)
	for _, s := range a1.Signers {
		signerSet[s] = true
	}
	for _, s := range a2.Signers {
		if signerSet[s] {
			return &EquivocationEvidence{
				NodeID:     s,
				First:      a1,
				Second:     a2,
				DetectedAt: time.Now(),
			}
		}
	}

	return nil
}
