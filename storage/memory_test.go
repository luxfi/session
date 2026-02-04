// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package storage

import (
	"testing"
)

func TestMemoryStore_BasicOperations(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	key := []byte("key")
	value := []byte("value")

	// Put
	if err := store.Put(key, value); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Has
	has, err := store.Has(key)
	if err != nil {
		t.Fatalf("Has failed: %v", err)
	}
	if !has {
		t.Error("expected key to exist")
	}

	// Get
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("expected %s, got %s", value, got)
	}

	// Delete
	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Has after delete
	has, err = store.Has(key)
	if err != nil {
		t.Fatalf("Has failed: %v", err)
	}
	if has {
		t.Error("expected key to not exist")
	}
}

func TestMemoryStore_NotFound(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	_, err := store.Get([]byte("nonexistent"))
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_Batch(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	batch := store.NewBatch()

	// Add operations
	batch.Put([]byte("key1"), []byte("value1"))
	batch.Put([]byte("key2"), []byte("value2"))
	batch.Delete([]byte("key3")) // Delete non-existent is ok

	if batch.Size() != 3 {
		t.Errorf("expected 3 operations, got %d", batch.Size())
	}

	// Write batch
	if err := batch.Write(); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify
	v1, _ := store.Get([]byte("key1"))
	if string(v1) != "value1" {
		t.Error("key1 value mismatch")
	}

	v2, _ := store.Get([]byte("key2"))
	if string(v2) != "value2" {
		t.Error("key2 value mismatch")
	}

	// Reset batch
	batch.Reset()
	if batch.Size() != 0 {
		t.Error("batch should be empty after reset")
	}
}

func TestMemoryStore_Iterator(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	// Insert data
	store.Put([]byte("a"), []byte("1"))
	store.Put([]byte("b"), []byte("2"))
	store.Put([]byte("c"), []byte("3"))
	store.Put([]byte("d"), []byte("4"))

	// Iterate over [b, d)
	iter := store.NewIterator([]byte("b"), []byte("d"))
	defer iter.Release()

	var keys []string
	for iter.Next() {
		keys = append(keys, string(iter.Key()))
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d: %v", len(keys), keys)
	}

	if err := iter.Error(); err != nil {
		t.Errorf("iterator error: %v", err)
	}
}

func TestMemoryStore_Closed(t *testing.T) {
	store := NewMemoryStore()
	store.Close()

	// Operations on closed store should fail
	_, err := store.Get([]byte("key"))
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}

	if err := store.Put([]byte("key"), []byte("value")); err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}

	if err := store.Delete([]byte("key")); err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}

	_, err = store.Has([]byte("key"))
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestNamespace(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	ns := NewNamespace(store, []byte("prefix:"))

	// Put in namespace
	if err := ns.Put([]byte("key"), []byte("value")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get from namespace
	got, err := ns.Get([]byte("key"))
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got) != "value" {
		t.Error("value mismatch")
	}

	// Verify actual key in underlying store
	actual, err := store.Get([]byte("prefix:key"))
	if err != nil {
		t.Fatalf("Get from underlying store failed: %v", err)
	}
	if string(actual) != "value" {
		t.Error("underlying value mismatch")
	}

	// Original key should not exist
	_, err = store.Get([]byte("key"))
	if err != ErrNotFound {
		t.Error("expected key without prefix to not exist")
	}
}
