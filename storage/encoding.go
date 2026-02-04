// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package storage

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/session/core"
)

// Codec handles serialization and deserialization.
// Default implementation uses a simple binary format.
type Codec interface {
	// EncodeSession encodes a session to bytes.
	EncodeSession(s *core.Session) ([]byte, error)

	// DecodeSession decodes bytes to a session.
	DecodeSession(data []byte) (*core.Session, error)

	// EncodeStep encodes a step to bytes.
	EncodeStep(s *core.Step) ([]byte, error)

	// DecodeStep decodes bytes to a step.
	DecodeStep(data []byte) (*core.Step, error)
}

// BinaryCodec is a simple binary encoder/decoder.
type BinaryCodec struct{}

// NewBinaryCodec creates a new binary codec.
func NewBinaryCodec() *BinaryCodec {
	return &BinaryCodec{}
}

// EncodeSession encodes a session to bytes.
func (c *BinaryCodec) EncodeSession(s *core.Session) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil session")
	}

	// Calculate size
	size := 32 + 32 + 8 + 4 + len(s.Committee)*32 + 1 + 4 + 32 + 32 + 32 + 8 + 8 + 4 + len(s.Error)

	buf := make([]byte, size)
	offset := 0

	// ID
	copy(buf[offset:], s.ID[:])
	offset += 32

	// ServiceID
	copy(buf[offset:], s.ServiceID[:])
	offset += 32

	// Epoch
	binary.BigEndian.PutUint64(buf[offset:], s.Epoch)
	offset += 8

	// Committee length + data
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(s.Committee)))
	offset += 4
	for _, c := range s.Committee {
		copy(buf[offset:], c[:])
		offset += 32
	}

	// State
	buf[offset] = byte(s.State)
	offset++

	// CurrentStep
	binary.BigEndian.PutUint32(buf[offset:], s.CurrentStep)
	offset += 4

	// OutputHash
	copy(buf[offset:], s.OutputHash[:])
	offset += 32

	// OracleRoot
	copy(buf[offset:], s.OracleRoot[:])
	offset += 32

	// ReceiptsRoot
	copy(buf[offset:], s.ReceiptsRoot[:])
	offset += 32

	// CreatedAt (unix nano)
	binary.BigEndian.PutUint64(buf[offset:], uint64(s.CreatedAt.UnixNano()))
	offset += 8

	// FinalizedAt (unix nano)
	binary.BigEndian.PutUint64(buf[offset:], uint64(s.FinalizedAt.UnixNano()))
	offset += 8

	// Error length + data
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(s.Error)))
	offset += 4
	copy(buf[offset:], s.Error)

	return buf, nil
}

// DecodeSession decodes bytes to a session.
func (c *BinaryCodec) DecodeSession(data []byte) (*core.Session, error) {
	if len(data) < 32+32+8+4+1+4+32+32+32+8+8+4 {
		return nil, errors.New("data too short")
	}

	s := &core.Session{}
	offset := 0

	// ID
	copy(s.ID[:], data[offset:])
	offset += 32

	// ServiceID
	copy(s.ServiceID[:], data[offset:])
	offset += 32

	// Epoch
	s.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Committee
	committeeLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	s.Committee = make([]core.ID, committeeLen)
	for i := uint32(0); i < committeeLen; i++ {
		copy(s.Committee[i][:], data[offset:])
		offset += 32
	}

	// State
	s.State = core.SessionState(data[offset])
	offset++

	// CurrentStep
	s.CurrentStep = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// OutputHash
	copy(s.OutputHash[:], data[offset:])
	offset += 32

	// OracleRoot
	copy(s.OracleRoot[:], data[offset:])
	offset += 32

	// ReceiptsRoot
	copy(s.ReceiptsRoot[:], data[offset:])
	offset += 32

	// Skip timestamps and error for now (simplified)

	return s, nil
}

// EncodeStep encodes a step to bytes.
func (c *BinaryCodec) EncodeStep(s *core.Step) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil step")
	}

	// Fixed size: 4+1+32+4+32+32+32+32+32+1+8+8 = 218 bytes
	buf := make([]byte, 218)
	offset := 0

	// StepIndex
	binary.BigEndian.PutUint32(buf[offset:], s.StepIndex)
	offset += 4

	// Kind
	buf[offset] = byte(s.Kind)
	offset++

	// RequestID
	copy(buf[offset:], s.RequestID[:])
	offset += 32

	// RetryIndex
	binary.BigEndian.PutUint32(buf[offset:], s.RetryIndex)
	offset += 4

	// TxID
	copy(buf[offset:], s.TxID[:])
	offset += 32

	// InputHash
	copy(buf[offset:], s.InputHash[:])
	offset += 32

	// OutputHash
	copy(buf[offset:], s.OutputHash[:])
	offset += 32

	// OracleCommitRoot
	copy(buf[offset:], s.OracleCommitRoot[:])
	offset += 32

	// AttestationID
	copy(buf[offset:], s.AttestationID[:])
	offset += 32

	// State
	buf[offset] = byte(s.State)
	offset++

	// StartedAt
	binary.BigEndian.PutUint64(buf[offset:], uint64(s.StartedAt.UnixNano()))
	offset += 8

	// CompletedAt
	binary.BigEndian.PutUint64(buf[offset:], uint64(s.CompletedAt.UnixNano()))

	return buf, nil
}

// DecodeStep decodes bytes to a step.
func (c *BinaryCodec) DecodeStep(data []byte) (*core.Step, error) {
	if len(data) < 218 {
		return nil, errors.New("data too short")
	}

	s := &core.Step{}
	offset := 0

	// StepIndex
	s.StepIndex = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Kind
	s.Kind = core.StepKind(data[offset])
	offset++

	// RequestID
	copy(s.RequestID[:], data[offset:])
	offset += 32

	// RetryIndex
	s.RetryIndex = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// TxID
	copy(s.TxID[:], data[offset:])
	offset += 32

	// InputHash
	copy(s.InputHash[:], data[offset:])
	offset += 32

	// OutputHash
	copy(s.OutputHash[:], data[offset:])
	offset += 32

	// OracleCommitRoot
	copy(s.OracleCommitRoot[:], data[offset:])
	offset += 32

	// AttestationID
	copy(s.AttestationID[:], data[offset:])
	offset += 32

	// State
	s.State = core.StepState(data[offset])

	return s, nil
}
