// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package protocol

import (
	"testing"

	"github.com/luxfi/session/core"
)

func TestNewOracleRequest(t *testing.T) {
	serviceID := core.Hash([]byte("service"))
	sessionID := core.Hash([]byte("session"))
	txID := core.Hash([]byte("tx"))
	inputHash := core.Hash([]byte("input"))

	req := NewOracleRequest(serviceID, sessionID, txID, inputHash, 0, 0, RequestKindWrite)

	if req.ServiceID != serviceID {
		t.Error("service ID mismatch")
	}

	if req.SessionID != sessionID {
		t.Error("session ID mismatch")
	}

	if req.Status != RequestStatusPending {
		t.Error("expected pending status")
	}

	if req.Kind != RequestKindWrite {
		t.Error("expected write kind")
	}

	// Verify deterministic ID
	expectedID := core.ComputeRequestID(serviceID, sessionID, txID, 0, 0)
	if req.ID != expectedID {
		t.Error("request ID mismatch")
	}
}

func TestNewOracleRecord(t *testing.T) {
	requestID := core.Hash([]byte("request"))
	submitterID := core.Hash([]byte("submitter"))
	data := []byte("test data")
	signature := []byte("sig")

	record := NewOracleRecord(requestID, submitterID, data, signature)

	if record.RequestID != requestID {
		t.Error("request ID mismatch")
	}

	if record.SubmitterID != submitterID {
		t.Error("submitter ID mismatch")
	}

	if record.DataHash != core.Hash(data) {
		t.Error("data hash mismatch")
	}
}

func TestComputeMerkleRoot(t *testing.T) {
	// Empty records
	root := ComputeMerkleRoot(nil)
	if !root.Empty() {
		t.Error("expected empty root for no records")
	}

	// Single record
	requestID := core.Hash([]byte("request"))
	submitterID := core.Hash([]byte("submitter"))
	record1 := NewOracleRecord(requestID, submitterID, []byte("data1"), nil)

	root = ComputeMerkleRoot([]*OracleRecord{record1})
	if root != record1.DataHash {
		t.Error("single record root should be record hash")
	}

	// Two records
	record2 := NewOracleRecord(requestID, submitterID, []byte("data2"), nil)
	root = ComputeMerkleRoot([]*OracleRecord{record1, record2})
	if root.Empty() {
		t.Error("expected non-empty root")
	}

	// Verify deterministic
	root2 := ComputeMerkleRoot([]*OracleRecord{record1, record2})
	if root != root2 {
		t.Error("merkle root should be deterministic")
	}
}

func TestRequestKindString(t *testing.T) {
	tests := []struct {
		kind     RequestKind
		expected string
	}{
		{RequestKindWrite, "write"},
		{RequestKindRead, "read"},
		{RequestKind(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.expected {
			t.Errorf("RequestKind(%d).String() = %s, want %s", tt.kind, got, tt.expected)
		}
	}
}

func TestRequestStatusString(t *testing.T) {
	tests := []struct {
		status   RequestStatus
		expected string
	}{
		{RequestStatusPending, "pending"},
		{RequestStatusCommitted, "committed"},
		{RequestStatusAttested, "attested"},
		{RequestStatus(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.expected {
			t.Errorf("RequestStatus(%d).String() = %s, want %s", tt.status, got, tt.expected)
		}
	}
}
