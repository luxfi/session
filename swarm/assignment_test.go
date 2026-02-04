// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swarm

import (
	"testing"

	"github.com/luxfi/session/core"
)

func TestAssignCommittee(t *testing.T) {
	assigner := NewAssigner(nil)

	serviceID := core.Hash([]byte("service"))
	epoch := uint64(100)
	epochRandomness := core.Hash([]byte("randomness"))

	// Create eligible nodes
	eligibleNodes := make([]core.ID, 10)
	for i := 0; i < 10; i++ {
		eligibleNodes[i] = core.Hash([]byte{byte(i)})
	}

	committee, err := assigner.AssignCommittee(serviceID, epoch, epochRandomness, eligibleNodes)
	if err != nil {
		t.Fatalf("AssignCommittee failed: %v", err)
	}

	if len(committee) == 0 {
		t.Error("expected non-empty committee")
	}

	// Same inputs should produce same committee (deterministic)
	committee2, err := assigner.AssignCommittee(serviceID, epoch, epochRandomness, eligibleNodes)
	if err != nil {
		t.Fatalf("AssignCommittee failed: %v", err)
	}

	if len(committee) != len(committee2) {
		t.Error("committee sizes should match")
	}

	for i := range committee {
		if committee[i] != committee2[i] {
			t.Error("committee members should match")
		}
	}

	// Different epoch should produce different committee
	committee3, _ := assigner.AssignCommittee(serviceID, epoch+1, epochRandomness, eligibleNodes)
	same := true
	for i := range committee {
		if committee[i] != committee3[i] {
			same = false
			break
		}
	}
	if same && len(committee) > 1 {
		t.Error("different epoch should likely produce different committee")
	}
}

func TestAssignCommittee_NotEnoughNodes(t *testing.T) {
	config := DefaultConfig()
	config.MinCommitteeSize = 5
	assigner := NewAssigner(config)

	serviceID := core.Hash([]byte("service"))
	epoch := uint64(100)
	epochRandomness := core.Hash([]byte("randomness"))

	// Only 3 nodes, but min is 5
	eligibleNodes := make([]core.ID, 3)
	for i := 0; i < 3; i++ {
		eligibleNodes[i] = core.Hash([]byte{byte(i)})
	}

	_, err := assigner.AssignCommittee(serviceID, epoch, epochRandomness, eligibleNodes)
	if err == nil {
		t.Error("expected error for not enough nodes")
	}
}

func TestQuorumSize(t *testing.T) {
	config := &Config{
		QuorumThreshold: 0.67,
	}
	assigner := NewAssigner(config)

	tests := []struct {
		committeeSize int
		expectedMin   int
	}{
		{3, 3},  // 3 * 0.67 + 1 = 3
		{7, 5},  // 7 * 0.67 + 1 = 5.69 → 5
		{10, 7}, // 10 * 0.67 + 1 = 7.7 → 7
		{21, 15},
	}

	for _, tt := range tests {
		quorum := assigner.QuorumSize(tt.committeeSize)
		if quorum < tt.expectedMin {
			t.Errorf("committee=%d: quorum=%d, expected at least %d", tt.committeeSize, quorum, tt.expectedMin)
		}
	}
}

func TestIsQuorum(t *testing.T) {
	config := &Config{
		QuorumThreshold: 0.67,
	}
	assigner := NewAssigner(config)

	// Committee of 7
	committeeSize := 7
	quorum := assigner.QuorumSize(committeeSize)

	// Below quorum
	if assigner.IsQuorum(quorum-1, committeeSize) {
		t.Error("should not be quorum")
	}

	// At quorum
	if !assigner.IsQuorum(quorum, committeeSize) {
		t.Error("should be quorum")
	}

	// Above quorum
	if !assigner.IsQuorum(quorum+1, committeeSize) {
		t.Error("should be quorum")
	}
}

func TestNewEpochBeacon(t *testing.T) {
	epoch := uint64(100)
	randomness := core.Hash([]byte("random"))
	previousBeacon := core.Hash([]byte("previous"))

	beacon := NewEpochBeacon(epoch, randomness, previousBeacon)

	if beacon.Epoch != epoch {
		t.Error("epoch mismatch")
	}

	if beacon.Randomness != randomness {
		t.Error("randomness mismatch")
	}

	if beacon.PreviousBeacon != previousBeacon {
		t.Error("previous beacon mismatch")
	}
}
