// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"testing"
)

func TestComputeSessionID(t *testing.T) {
	serviceID := Hash([]byte("service"))
	epoch := uint64(100)
	txID := Hash([]byte("tx"))

	id1 := ComputeSessionID(serviceID, epoch, txID)
	id2 := ComputeSessionID(serviceID, epoch, txID)

	// Same inputs should produce same ID
	if id1 != id2 {
		t.Error("same inputs should produce same session ID")
	}

	// Different epoch should produce different ID
	id3 := ComputeSessionID(serviceID, epoch+1, txID)
	if id1 == id3 {
		t.Error("different epoch should produce different session ID")
	}

	// Different service should produce different ID
	id4 := ComputeSessionID(Hash([]byte("other")), epoch, txID)
	if id1 == id4 {
		t.Error("different service should produce different session ID")
	}
}

func TestNewSession(t *testing.T) {
	serviceID := Hash([]byte("service"))
	epoch := uint64(100)
	txID := Hash([]byte("tx"))
	committee := []ID{Hash([]byte("node1")), Hash([]byte("node2"))}

	session := NewSession(serviceID, epoch, txID, committee)

	if session.State != SessionStatePending {
		t.Errorf("expected pending state, got %v", session.State)
	}

	if session.ServiceID != serviceID {
		t.Error("service ID mismatch")
	}

	if session.Epoch != epoch {
		t.Error("epoch mismatch")
	}

	if len(session.Committee) != 2 {
		t.Error("committee length mismatch")
	}

	expectedID := ComputeSessionID(serviceID, epoch, txID)
	if session.ID != expectedID {
		t.Error("session ID mismatch")
	}
}

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state    SessionState
		expected string
	}{
		{SessionStatePending, "pending"},
		{SessionStateRunning, "running"},
		{SessionStateWaitingIO, "waiting_io"},
		{SessionStateFinalized, "finalized"},
		{SessionStateFailed, "failed"},
		{SessionState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("SessionState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}
