// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"testing"
)

func TestIDEmpty(t *testing.T) {
	var id ID
	if !id.Empty() {
		t.Error("expected empty ID")
	}

	id[0] = 1
	if id.Empty() {
		t.Error("expected non-empty ID")
	}
}

func TestIDString(t *testing.T) {
	id := ID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	s := id.String()
	if len(s) != 64 {
		t.Errorf("expected 64 char string, got %d", len(s))
	}
	if s[:16] != "0123456789abcdef" {
		t.Errorf("unexpected string prefix: %s", s[:16])
	}
}

func TestHash(t *testing.T) {
	data := []byte("test data")
	h1 := Hash(data)
	h2 := Hash(data)

	if h1 != h2 {
		t.Error("same input should produce same hash")
	}

	h3 := Hash([]byte("different data"))
	if h1 == h3 {
		t.Error("different input should produce different hash")
	}
}

func TestHashWithDomain(t *testing.T) {
	data := []byte("test")
	h1 := HashWithDomain("domain1", data)
	h2 := HashWithDomain("domain2", data)

	if h1 == h2 {
		t.Error("different domains should produce different hashes")
	}
}

func TestHashMulti(t *testing.T) {
	h1 := HashMulti([]byte("a"), []byte("b"), []byte("c"))
	h2 := HashMulti([]byte("a"), []byte("b"), []byte("c"))

	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}

	// Different grouping should still produce deterministic results
	h3 := HashMulti([]byte("ab"), []byte("c"))
	h4 := HashMulti([]byte("ab"), []byte("c"))
	if h3 != h4 {
		t.Error("same inputs should produce same hash")
	}
}

func TestUint64ToBytes(t *testing.T) {
	b := Uint64ToBytes(0x0102030405060708)
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	for i := range expected {
		if b[i] != expected[i] {
			t.Errorf("byte %d: expected %02x, got %02x", i, expected[i], b[i])
		}
	}
}

func TestBytesToUint64(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	v := BytesToUint64(b)

	if v != 0x0102030405060708 {
		t.Errorf("expected 0x0102030405060708, got 0x%x", v)
	}
}

func TestUint32ToBytes(t *testing.T) {
	b := Uint32ToBytes(0x01020304)
	expected := []byte{0x01, 0x02, 0x03, 0x04}

	for i := range expected {
		if b[i] != expected[i] {
			t.Errorf("byte %d: expected %02x, got %02x", i, expected[i], b[i])
		}
	}
}

func TestBytesToUint32(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04}
	v := BytesToUint32(b)

	if v != 0x01020304 {
		t.Errorf("expected 0x01020304, got 0x%x", v)
	}
}
