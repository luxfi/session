// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package core provides shared types and utilities for the session layer.
// These types are imported by both on-chain (lux/node VMs) and off-chain (sessiond) code.
package core

import (
	"crypto/sha256"
	"encoding/binary"
)

// ID is a 32-byte identifier used throughout the session layer.
// This is the canonical ID type - all other ID types derive from this.
type ID [32]byte

// Empty returns true if the ID is all zeros.
func (id ID) Empty() bool {
	return id == ID{}
}

// Bytes returns the ID as a byte slice.
func (id ID) Bytes() []byte {
	return id[:]
}

// String returns a hex representation of the ID.
func (id ID) String() string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, 64)
	for i, b := range id {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// IDFromBytes creates an ID from a byte slice.
func IDFromBytes(b []byte) ID {
	var id ID
	copy(id[:], b)
	return id
}

// Hash computes the SHA256 hash of the input and returns it as an ID.
func Hash(data []byte) ID {
	return ID(sha256.Sum256(data))
}

// HashWithDomain computes a domain-separated hash.
// domain || data → SHA256
func HashWithDomain(domain string, data []byte) ID {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(data)
	var result ID
	copy(result[:], h.Sum(nil))
	return result
}

// HashMulti computes a hash over multiple byte slices.
func HashMulti(parts ...[]byte) ID {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var result ID
	copy(result[:], h.Sum(nil))
	return result
}

// Uint64ToBytes converts a uint64 to big-endian bytes.
func Uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// Uint32ToBytes converts a uint32 to big-endian bytes.
func Uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// BytesToUint64 converts big-endian bytes to uint64.
func BytesToUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// BytesToUint32 converts big-endian bytes to uint32.
func BytesToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
