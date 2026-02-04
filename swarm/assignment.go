// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package swarm implements epoch-based swarm assignment for session workloads.
// Swarms are dynamically formed committees of nodes assigned to execute sessions.
package swarm

import (
	"errors"
	"sort"

	"github.com/luxfi/session/core"
)

// Config holds swarm assignment configuration.
type Config struct {
	// MinCommitteeSize is the minimum number of nodes in a committee
	MinCommitteeSize int

	// MaxCommitteeSize is the maximum number of nodes in a committee
	MaxCommitteeSize int

	// QuorumThreshold is the fraction of committee required for quorum (e.g., 0.67)
	QuorumThreshold float64
}

// DefaultConfig returns the default swarm configuration.
func DefaultConfig() *Config {
	return &Config{
		MinCommitteeSize: 3,
		MaxCommitteeSize: 21,
		QuorumThreshold:  0.67,
	}
}

// Assigner handles epoch-based swarm assignment.
type Assigner struct {
	config *Config
}

// NewAssigner creates a new swarm assigner.
func NewAssigner(config *Config) *Assigner {
	if config == nil {
		config = DefaultConfig()
	}
	return &Assigner{config: config}
}

// AssignCommittee assigns a committee for a session based on epoch randomness.
// Uses deterministic selection based on epoch beacon and service ID.
func (a *Assigner) AssignCommittee(
	serviceID core.ID,
	epoch uint64,
	epochRandomness core.ID,
	eligibleNodes []core.ID,
) ([]core.ID, error) {
	if len(eligibleNodes) < a.config.MinCommitteeSize {
		return nil, errors.New("not enough eligible nodes")
	}

	// Compute selection seed: H(epoch_randomness || service_id || epoch)
	seed := core.HashMulti(
		epochRandomness[:],
		serviceID[:],
		core.Uint64ToBytes(epoch),
	)

	// Sort nodes deterministically by score
	type scoredNode struct {
		id    core.ID
		score core.ID
	}

	scored := make([]scoredNode, len(eligibleNodes))
	for i, nodeID := range eligibleNodes {
		// Score = H(seed || node_id)
		scored[i] = scoredNode{
			id:    nodeID,
			score: core.HashMulti(seed[:], nodeID[:]),
		}
	}

	// Sort by score (lexicographic comparison of 32-byte hashes)
	sort.Slice(scored, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if scored[i].score[k] < scored[j].score[k] {
				return true
			}
			if scored[i].score[k] > scored[j].score[k] {
				return false
			}
		}
		return false
	})

	// Select top N nodes
	committeeSize := a.config.MaxCommitteeSize
	if committeeSize > len(scored) {
		committeeSize = len(scored)
	}

	committee := make([]core.ID, committeeSize)
	for i := 0; i < committeeSize; i++ {
		committee[i] = scored[i].id
	}

	return committee, nil
}

// QuorumSize returns the number of nodes required for quorum.
func (a *Assigner) QuorumSize(committeeSize int) int {
	quorum := int(float64(committeeSize)*a.config.QuorumThreshold) + 1
	if quorum > committeeSize {
		return committeeSize
	}
	return quorum
}

// IsQuorum checks if the given number of participants meets quorum.
func (a *Assigner) IsQuorum(participants, committeeSize int) bool {
	return participants >= a.QuorumSize(committeeSize)
}

// EpochBeacon represents epoch randomness for swarm assignment.
type EpochBeacon struct {
	// Epoch number
	Epoch uint64 `json:"epoch"`

	// Randomness is the VRF output for this epoch
	Randomness core.ID `json:"randomness"`

	// PreviousBeacon is the hash of the previous epoch's beacon
	PreviousBeacon core.ID `json:"previousBeacon"`

	// AttestationID is the threshold attestation over this beacon
	AttestationID core.ID `json:"attestationId"`
}

// ComputeBeaconID computes a deterministic beacon ID.
func ComputeBeaconID(epoch uint64, randomness, previousBeacon core.ID) core.ID {
	return core.HashMulti(
		[]byte("LUX:EpochBeacon:v1"),
		core.Uint64ToBytes(epoch),
		randomness[:],
		previousBeacon[:],
	)
}

// NewEpochBeacon creates a new epoch beacon.
func NewEpochBeacon(epoch uint64, randomness, previousBeacon core.ID) *EpochBeacon {
	return &EpochBeacon{
		Epoch:          epoch,
		Randomness:     randomness,
		PreviousBeacon: previousBeacon,
	}
}
