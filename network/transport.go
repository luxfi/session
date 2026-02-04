// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package network provides P2P networking abstractions for the session layer.
// Supports post-quantum secure transport using hybrid key encapsulation.
package network

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/luxfi/session/core"
)

// MessageType identifies the type of network message.
type MessageType uint8

const (
	MessageTypeUnknown MessageType = iota
	MessageTypeHandshake
	MessageTypeSessionCreate
	MessageTypeSessionStart
	MessageTypeOracleRequest
	MessageTypeOracleRecord
	MessageTypeOracleCommit
	MessageTypeAttestation
	MessageTypeReceipt
	MessageTypeHeartbeat
	MessageTypePing
	MessageTypePong
)

func (t MessageType) String() string {
	switch t {
	case MessageTypeHandshake:
		return "handshake"
	case MessageTypeSessionCreate:
		return "session_create"
	case MessageTypeSessionStart:
		return "session_start"
	case MessageTypeOracleRequest:
		return "oracle_request"
	case MessageTypeOracleRecord:
		return "oracle_record"
	case MessageTypeOracleCommit:
		return "oracle_commit"
	case MessageTypeAttestation:
		return "attestation"
	case MessageTypeReceipt:
		return "receipt"
	case MessageTypeHeartbeat:
		return "heartbeat"
	case MessageTypePing:
		return "ping"
	case MessageTypePong:
		return "pong"
	default:
		return "unknown"
	}
}

// Message represents a network message.
type Message struct {
	// Type identifies the message type
	Type MessageType `json:"type"`

	// From is the sender's node ID
	From core.ID `json:"from"`

	// To is the recipient's node ID (empty for broadcast)
	To core.ID `json:"to,omitempty"`

	// Payload is the message data
	Payload []byte `json:"payload"`

	// Timestamp when the message was created
	Timestamp time.Time `json:"timestamp"`

	// Signature from the sender
	Signature []byte `json:"signature,omitempty"`
}

// Transport is the core networking interface.
type Transport interface {
	// Start starts the transport.
	Start(ctx context.Context) error

	// Stop stops the transport.
	Stop() error

	// Send sends a message to a specific node.
	Send(ctx context.Context, to core.ID, msg *Message) error

	// Broadcast sends a message to all known peers.
	Broadcast(ctx context.Context, msg *Message) error

	// Receive returns a channel for receiving messages.
	Receive() <-chan *Message

	// Connect connects to a peer.
	Connect(ctx context.Context, addr string) error

	// Disconnect disconnects from a peer.
	Disconnect(nodeID core.ID) error

	// Peers returns the list of connected peer IDs.
	Peers() []core.ID

	// LocalID returns the local node ID.
	LocalID() core.ID
}

// Connection represents a connection to a peer.
type Connection interface {
	// Read reads data from the connection.
	Read(p []byte) (n int, err error)

	// Write writes data to the connection.
	Write(p []byte) (n int, err error)

	// Close closes the connection.
	Close() error

	// RemoteID returns the remote node ID.
	RemoteID() core.ID

	// RemoteAddr returns the remote address.
	RemoteAddr() string

	// LocalAddr returns the local address.
	LocalAddr() string
}

// Listener listens for incoming connections.
type Listener interface {
	// Accept accepts a new connection.
	Accept() (Connection, error)

	// Close closes the listener.
	Close() error

	// Addr returns the listener address.
	Addr() string
}

// Dialer dials outgoing connections.
type Dialer interface {
	// Dial dials a connection to the address.
	Dial(ctx context.Context, addr string) (Connection, error)
}

// Handler processes incoming messages.
type Handler interface {
	// Handle processes a message and optionally returns a response.
	Handle(ctx context.Context, msg *Message) (*Message, error)
}

// HandlerFunc is a function that implements Handler.
type HandlerFunc func(ctx context.Context, msg *Message) (*Message, error)

// Handle implements Handler.
func (f HandlerFunc) Handle(ctx context.Context, msg *Message) (*Message, error) {
	return f(ctx, msg)
}

// Router routes messages to handlers.
type Router struct {
	handlers map[MessageType]Handler
}

// NewRouter creates a new message router.
func NewRouter() *Router {
	return &Router{
		handlers: make(map[MessageType]Handler),
	}
}

// Register registers a handler for a message type.
func (r *Router) Register(msgType MessageType, handler Handler) {
	r.handlers[msgType] = handler
}

// RegisterFunc registers a handler function for a message type.
func (r *Router) RegisterFunc(msgType MessageType, f HandlerFunc) {
	r.handlers[msgType] = f
}

// Route routes a message to its handler.
func (r *Router) Route(ctx context.Context, msg *Message) (*Message, error) {
	handler, ok := r.handlers[msg.Type]
	if !ok {
		return nil, errors.New("no handler for message type")
	}
	return handler.Handle(ctx, msg)
}

// StreamConn wraps a connection with framed message reading/writing.
type StreamConn struct {
	conn Connection
}

// NewStreamConn creates a new stream connection wrapper.
func NewStreamConn(conn Connection) *StreamConn {
	return &StreamConn{conn: conn}
}

// WriteMessage writes a framed message.
func (s *StreamConn) WriteMessage(msg *Message) error {
	// Simple length-prefixed framing
	// In production, use proper serialization
	data := encodeMessage(msg)
	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(data) >> 24)
	lenBuf[1] = byte(len(data) >> 16)
	lenBuf[2] = byte(len(data) >> 8)
	lenBuf[3] = byte(len(data))

	_, err := s.conn.Write(lenBuf)
	if err != nil {
		return err
	}
	_, err = s.conn.Write(data)
	return err
}

// ReadMessage reads a framed message.
func (s *StreamConn) ReadMessage() (*Message, error) {
	lenBuf := make([]byte, 4)
	_, err := io.ReadFull(s.conn, lenBuf)
	if err != nil {
		return nil, err
	}

	length := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	if length > 1<<20 { // 1MB max
		return nil, errors.New("message too large")
	}

	data := make([]byte, length)
	_, err = io.ReadFull(s.conn, data)
	if err != nil {
		return nil, err
	}

	return decodeMessage(data)
}

// Close closes the underlying connection.
func (s *StreamConn) Close() error {
	return s.conn.Close()
}

// encodeMessage encodes a message to bytes using length-prefixed binary format.
func encodeMessage(msg *Message) []byte {
	buf := make([]byte, 1+32+32+4+len(msg.Payload)+8+4+len(msg.Signature))
	offset := 0

	buf[offset] = byte(msg.Type)
	offset++

	copy(buf[offset:], msg.From[:])
	offset += 32

	copy(buf[offset:], msg.To[:])
	offset += 32

	buf[offset] = byte(len(msg.Payload) >> 24)
	buf[offset+1] = byte(len(msg.Payload) >> 16)
	buf[offset+2] = byte(len(msg.Payload) >> 8)
	buf[offset+3] = byte(len(msg.Payload))
	offset += 4

	copy(buf[offset:], msg.Payload)
	offset += len(msg.Payload)

	ts := msg.Timestamp.UnixNano()
	buf[offset] = byte(ts >> 56)
	buf[offset+1] = byte(ts >> 48)
	buf[offset+2] = byte(ts >> 40)
	buf[offset+3] = byte(ts >> 32)
	buf[offset+4] = byte(ts >> 24)
	buf[offset+5] = byte(ts >> 16)
	buf[offset+6] = byte(ts >> 8)
	buf[offset+7] = byte(ts)
	offset += 8

	buf[offset] = byte(len(msg.Signature) >> 24)
	buf[offset+1] = byte(len(msg.Signature) >> 16)
	buf[offset+2] = byte(len(msg.Signature) >> 8)
	buf[offset+3] = byte(len(msg.Signature))
	offset += 4

	copy(buf[offset:], msg.Signature)

	return buf
}

// decodeMessage decodes a message from bytes.
func decodeMessage(data []byte) (*Message, error) {
	if len(data) < 1+32+32+4 {
		return nil, errors.New("data too short")
	}

	msg := &Message{}
	offset := 0

	msg.Type = MessageType(data[offset])
	offset++

	copy(msg.From[:], data[offset:])
	offset += 32

	copy(msg.To[:], data[offset:])
	offset += 32

	payloadLen := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4

	if len(data) < offset+payloadLen+8+4 {
		return nil, errors.New("data too short for payload")
	}

	msg.Payload = make([]byte, payloadLen)
	copy(msg.Payload, data[offset:])
	offset += payloadLen

	ts := int64(data[offset])<<56 | int64(data[offset+1])<<48 | int64(data[offset+2])<<40 | int64(data[offset+3])<<32 |
		int64(data[offset+4])<<24 | int64(data[offset+5])<<16 | int64(data[offset+6])<<8 | int64(data[offset+7])
	msg.Timestamp = time.Unix(0, ts)
	offset += 8

	sigLen := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4

	if sigLen > 0 && len(data) >= offset+sigLen {
		msg.Signature = make([]byte, sigLen)
		copy(msg.Signature, data[offset:])
	}

	return msg, nil
}
