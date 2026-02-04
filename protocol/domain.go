// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package protocol defines the session protocol types and operations.
// This includes attestation domains, oracle operations, and receipt handling.
package protocol

import "github.com/luxfi/session/core"

// Domain represents an attestation domain.
// Domains provide cryptographic separation between different attestation types.
type Domain string

const (
	// DomainOracleWrite - attestation over oracle write commits
	DomainOracleWrite Domain = "oracle/write"
	// DomainOracleRead - attestation over oracle read commits
	DomainOracleRead Domain = "oracle/read"
	// DomainSessionComplete - attestation over session completion
	DomainSessionComplete Domain = "session/complete"
	// DomainEpochBeacon - attestation over epoch randomness beacon
	DomainEpochBeacon Domain = "epoch/beacon"
)

// DomainSeparator returns the cryptographic domain separator for an attestation domain.
// This is prefixed to all data before signing to prevent cross-domain replay attacks.
func DomainSeparator(d Domain) []byte {
	return []byte("LUX:QuantumAttest:" + string(d) + ":v1")
}

// DomainForStepKind returns the appropriate attestation domain for a step kind.
func DomainForStepKind(kind core.StepKind) Domain {
	switch kind {
	case core.StepKindWriteExternal:
		return DomainOracleWrite
	case core.StepKindReadExternal:
		return DomainOracleRead
	default:
		return ""
	}
}

// ValidateDomainForStep validates that an attestation domain matches the step kind.
func ValidateDomainForStep(domain Domain, kind core.StepKind) bool {
	return domain == DomainForStepKind(kind)
}
