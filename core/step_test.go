// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"testing"
)

func TestComputeRequestID(t *testing.T) {
	serviceID := Hash([]byte("service"))
	sessionID := Hash([]byte("session"))
	txID := Hash([]byte("tx"))
	step := uint32(0)
	retry := uint32(0)

	id1 := ComputeRequestID(serviceID, sessionID, txID, step, retry)
	id2 := ComputeRequestID(serviceID, sessionID, txID, step, retry)

	// Same inputs should produce same ID
	if id1 != id2 {
		t.Error("same inputs should produce same request ID")
	}

	// Different step should produce different ID
	id3 := ComputeRequestID(serviceID, sessionID, txID, step+1, retry)
	if id1 == id3 {
		t.Error("different step should produce different request ID")
	}

	// Different retry should produce different ID
	id4 := ComputeRequestID(serviceID, sessionID, txID, step, retry+1)
	if id1 == id4 {
		t.Error("different retry should produce different request ID")
	}
}

func TestStepKindString(t *testing.T) {
	tests := []struct {
		kind     StepKind
		expected string
	}{
		{StepKindCompute, "compute"},
		{StepKindWriteExternal, "write_external"},
		{StepKindReadExternal, "read_external"},
		{StepKind(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.expected {
			t.Errorf("StepKind(%d).String() = %s, want %s", tt.kind, got, tt.expected)
		}
	}
}

func TestStepKindRequiresOracle(t *testing.T) {
	if StepKindCompute.RequiresOracle() {
		t.Error("compute should not require oracle")
	}

	if !StepKindWriteExternal.RequiresOracle() {
		t.Error("write external should require oracle")
	}

	if !StepKindReadExternal.RequiresOracle() {
		t.Error("read external should require oracle")
	}
}

func TestStepStateString(t *testing.T) {
	tests := []struct {
		state    StepState
		expected string
	}{
		{StepStatePending, "pending"},
		{StepStateExecuting, "executing"},
		{StepStateWaiting, "waiting"},
		{StepStateCompleted, "completed"},
		{StepStateFailed, "failed"},
		{StepState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("StepState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestNewStep(t *testing.T) {
	txID := Hash([]byte("tx"))
	inputHash := Hash([]byte("input"))

	step := NewStep(0, StepKindCompute, txID, inputHash)

	if step.StepIndex != 0 {
		t.Error("step index mismatch")
	}

	if step.Kind != StepKindCompute {
		t.Error("kind mismatch")
	}

	if step.State != StepStatePending {
		t.Error("expected pending state")
	}

	if step.TxID != txID {
		t.Error("txID mismatch")
	}

	if step.InputHash != inputHash {
		t.Error("input hash mismatch")
	}
}

func TestNewOracleStep(t *testing.T) {
	serviceID := Hash([]byte("service"))
	sessionID := Hash([]byte("session"))
	txID := Hash([]byte("tx"))
	inputHash := Hash([]byte("input"))

	step := NewOracleStep(0, StepKindWriteExternal, serviceID, sessionID, txID, inputHash, 0)

	if step.Kind != StepKindWriteExternal {
		t.Error("kind mismatch")
	}

	expectedRequestID := ComputeRequestID(serviceID, sessionID, txID, 0, 0)
	if step.RequestID != expectedRequestID {
		t.Error("request ID mismatch")
	}
}
