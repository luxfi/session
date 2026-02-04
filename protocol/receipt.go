// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package protocol

import (
	"time"

	"github.com/luxfi/session/core"
)

// Receipt represents a relay receipt for message delivery.
type Receipt struct {
	// ID is the unique receipt identifier
	ID core.ID `json:"id"`

	// SessionID this receipt belongs to
	SessionID core.ID `json:"sessionId"`

	// StepIndex is the step that generated this message
	StepIndex uint32 `json:"stepIndex"`

	// MessageHash is the hash of the relayed message
	MessageHash core.ID `json:"messageHash"`

	// SenderID is the sending node
	SenderID core.ID `json:"senderId"`

	// ReceiverID is the receiving node
	ReceiverID core.ID `json:"receiverId"`

	// Timestamp of relay
	Timestamp time.Time `json:"timestamp"`

	// Signature from the relay node
	Signature []byte `json:"signature"`
}

// SignedReceipt is a receipt with additional verification data.
type SignedReceipt struct {
	*Receipt

	// RelayNodeID is the node that relayed the message
	RelayNodeID core.ID `json:"relayNodeId"`

	// RelaySignature is the signature from the relay node
	RelaySignature []byte `json:"relaySignature"`
}

// ReceiptCommit represents a committed set of receipts for a session.
type ReceiptCommit struct {
	// SessionID this commit is for
	SessionID core.ID `json:"sessionId"`

	// MerkleRoot of all receipts
	MerkleRoot core.ID `json:"merkleRoot"`

	// ReceiptCount is the number of receipts
	ReceiptCount uint32 `json:"receiptCount"`

	// Epoch when committed
	Epoch uint64 `json:"epoch"`

	// CommittedAt is when the commit was created
	CommittedAt time.Time `json:"committedAt"`
}

// ComputeReceiptID computes a deterministic receipt ID.
func ComputeReceiptID(sessionID core.ID, stepIndex uint32, messageHash, senderID, receiverID core.ID) core.ID {
	return core.HashMulti(
		[]byte("LUX:Receipt:v1"),
		sessionID[:],
		core.Uint32ToBytes(stepIndex),
		messageHash[:],
		senderID[:],
		receiverID[:],
	)
}

// NewReceipt creates a new receipt.
func NewReceipt(sessionID core.ID, stepIndex uint32, messageHash, senderID, receiverID core.ID, signature []byte) *Receipt {
	return &Receipt{
		ID:          ComputeReceiptID(sessionID, stepIndex, messageHash, senderID, receiverID),
		SessionID:   sessionID,
		StepIndex:   stepIndex,
		MessageHash: messageHash,
		SenderID:    senderID,
		ReceiverID:  receiverID,
		Timestamp:   time.Now(),
		Signature:   signature,
	}
}

// ComputeReceiptsRoot computes the Merkle root of a set of receipts.
func ComputeReceiptsRoot(receipts []*SignedReceipt) core.ID {
	if len(receipts) == 0 {
		return core.ID{}
	}

	// Get leaf hashes
	leaves := make([]core.ID, len(receipts))
	for i, r := range receipts {
		leaves[i] = r.ID
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

// ReceiptProof represents a Merkle inclusion proof for a receipt.
type ReceiptProof struct {
	*MerkleProof
	Receipt *SignedReceipt `json:"receipt"`
}

// VerifyReceiptProof verifies that a receipt is included in the receipts root.
func VerifyReceiptProof(root core.ID, proof *ReceiptProof) bool {
	return VerifyMerkleProof(root, proof.Receipt.ID, proof.MerkleProof)
}
