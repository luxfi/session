// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package storage

import (
	"bytes"
	"sort"
	"sync"
)

// MemoryStore is an in-memory implementation of Store.
// Useful for testing and ephemeral data.
type MemoryStore struct {
	data   map[string][]byte
	mu     sync.RWMutex
	closed bool
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string][]byte),
	}
}

// Get retrieves a value by key.
func (m *MemoryStore) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	value, ok := m.data[string(key)]
	if !ok {
		return nil, ErrNotFound
	}

	// Return a copy to prevent mutation
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// Put stores a value by key.
func (m *MemoryStore) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	// Store a copy to prevent mutation
	v := make([]byte, len(value))
	copy(v, value)
	m.data[string(key)] = v

	return nil
}

// Delete removes a key.
func (m *MemoryStore) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	delete(m.data, string(key))
	return nil
}

// Has checks if a key exists.
func (m *MemoryStore) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, ErrClosed
	}

	_, ok := m.data[string(key)]
	return ok, nil
}

// Close closes the store.
func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.data = nil
	return nil
}

// NewBatch creates a new batch.
func (m *MemoryStore) NewBatch() Batch {
	return &memoryBatch{
		store: m,
		ops:   make([]batchOp, 0),
	}
}

// NewIterator creates an iterator over keys in [start, end).
func (m *MemoryStore) NewIterator(start, end []byte) Iterator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect and sort keys in range
	var keys []string
	for k := range m.data {
		kb := []byte(k)
		if (start == nil || bytes.Compare(kb, start) >= 0) &&
			(end == nil || bytes.Compare(kb, end) < 0) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	return &memoryIterator{
		store: m,
		keys:  keys,
		index: -1,
	}
}

type batchOp struct {
	key    []byte
	value  []byte
	delete bool
}

type memoryBatch struct {
	store *MemoryStore
	ops   []batchOp
}

func (b *memoryBatch) Put(key, value []byte) error {
	k := make([]byte, len(key))
	v := make([]byte, len(value))
	copy(k, key)
	copy(v, value)
	b.ops = append(b.ops, batchOp{key: k, value: v})
	return nil
}

func (b *memoryBatch) Delete(key []byte) error {
	k := make([]byte, len(key))
	copy(k, key)
	b.ops = append(b.ops, batchOp{key: k, delete: true})
	return nil
}

func (b *memoryBatch) Write() error {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()

	if b.store.closed {
		return ErrClosed
	}

	for _, op := range b.ops {
		if op.delete {
			delete(b.store.data, string(op.key))
		} else {
			b.store.data[string(op.key)] = op.value
		}
	}

	return nil
}

func (b *memoryBatch) Reset() {
	b.ops = b.ops[:0]
}

func (b *memoryBatch) Size() int {
	return len(b.ops)
}

type memoryIterator struct {
	store *MemoryStore
	keys  []string
	index int
	err   error
}

func (it *memoryIterator) Next() bool {
	it.index++
	return it.index < len(it.keys)
}

func (it *memoryIterator) Key() []byte {
	if it.index < 0 || it.index >= len(it.keys) {
		return nil
	}
	return []byte(it.keys[it.index])
}

func (it *memoryIterator) Value() []byte {
	if it.index < 0 || it.index >= len(it.keys) {
		return nil
	}
	it.store.mu.RLock()
	defer it.store.mu.RUnlock()
	return it.store.data[it.keys[it.index]]
}

func (it *memoryIterator) Error() error {
	return it.err
}

func (it *memoryIterator) Release() {
	it.keys = nil
}

// Ensure MemoryStore implements all interfaces.
var (
	_ Store         = (*MemoryStore)(nil)
	_ BatchWriter   = (*MemoryStore)(nil)
	_ IterableStore = (*MemoryStore)(nil)
)
