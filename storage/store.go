// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package storage provides storage abstractions for the session layer.
// Implementations can use different backends (memory, LevelDB, Pebble, etc.)
package storage

import (
	"errors"

	"github.com/luxfi/session/core"
)

var (
	// ErrNotFound is returned when a key is not found.
	ErrNotFound = errors.New("not found")

	// ErrClosed is returned when the store is closed.
	ErrClosed = errors.New("store closed")
)

// Store is the core key-value storage interface.
// All storage implementations must satisfy this interface.
type Store interface {
	// Get retrieves a value by key.
	Get(key []byte) ([]byte, error)

	// Put stores a value by key.
	Put(key, value []byte) error

	// Delete removes a key.
	Delete(key []byte) error

	// Has checks if a key exists.
	Has(key []byte) (bool, error)

	// Close closes the store.
	Close() error
}

// BatchWriter supports batch writes for efficiency.
type BatchWriter interface {
	Store

	// NewBatch creates a new batch.
	NewBatch() Batch
}

// Batch represents a batch of writes.
type Batch interface {
	// Put adds a put operation to the batch.
	Put(key, value []byte) error

	// Delete adds a delete operation to the batch.
	Delete(key []byte) error

	// Write executes all operations in the batch.
	Write() error

	// Reset clears the batch.
	Reset()

	// Size returns the number of operations in the batch.
	Size() int
}

// Iterator iterates over keys in a range.
type Iterator interface {
	// Next advances the iterator.
	Next() bool

	// Key returns the current key.
	Key() []byte

	// Value returns the current value.
	Value() []byte

	// Error returns any error encountered.
	Error() error

	// Release releases the iterator.
	Release()
}

// IterableStore supports iteration over keys.
type IterableStore interface {
	Store

	// NewIterator creates an iterator over keys in [start, end).
	NewIterator(start, end []byte) Iterator
}

// Namespace prefixes keys for logical separation.
type Namespace struct {
	prefix []byte
	store  Store
}

// NewNamespace creates a namespaced view of a store.
func NewNamespace(store Store, prefix []byte) *Namespace {
	return &Namespace{
		prefix: prefix,
		store:  store,
	}
}

func (n *Namespace) prefixKey(key []byte) []byte {
	prefixed := make([]byte, len(n.prefix)+len(key))
	copy(prefixed, n.prefix)
	copy(prefixed[len(n.prefix):], key)
	return prefixed
}

// Get retrieves a value by key.
func (n *Namespace) Get(key []byte) ([]byte, error) {
	return n.store.Get(n.prefixKey(key))
}

// Put stores a value by key.
func (n *Namespace) Put(key, value []byte) error {
	return n.store.Put(n.prefixKey(key), value)
}

// Delete removes a key.
func (n *Namespace) Delete(key []byte) error {
	return n.store.Delete(n.prefixKey(key))
}

// Has checks if a key exists.
func (n *Namespace) Has(key []byte) (bool, error) {
	return n.store.Has(n.prefixKey(key))
}

// Close closes the underlying store.
func (n *Namespace) Close() error {
	return n.store.Close()
}

// Storage namespaces (prefixes).
var (
	PrefixSession     = []byte("session:")
	PrefixStep        = []byte("step:")
	PrefixOracle      = []byte("oracle:")
	PrefixReceipt     = []byte("receipt:")
	PrefixAttestation = []byte("attest:")
	PrefixNode        = []byte("node:")
	PrefixEpoch       = []byte("epoch:")
)

// SessionStore provides session-specific storage operations.
type SessionStore struct {
	store Store
	codec *BinaryCodec
}

// NewSessionStore creates a new session store.
func NewSessionStore(store Store) *SessionStore {
	return &SessionStore{
		store: NewNamespace(store, PrefixSession),
		codec: NewBinaryCodec(),
	}
}

// Get retrieves a session by ID.
func (s *SessionStore) Get(id core.ID) (*core.Session, error) {
	data, err := s.store.Get(id[:])
	if err != nil {
		return nil, err
	}
	return s.codec.DecodeSession(data)
}

// Put stores a session.
func (s *SessionStore) Put(session *core.Session) error {
	data, err := s.codec.EncodeSession(session)
	if err != nil {
		return err
	}
	return s.store.Put(session.ID[:], data)
}

// Delete removes a session.
func (s *SessionStore) Delete(id core.ID) error {
	return s.store.Delete(id[:])
}

// Has checks if a session exists.
func (s *SessionStore) Has(id core.ID) (bool, error) {
	return s.store.Has(id[:])
}
