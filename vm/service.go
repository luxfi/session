// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"encoding/hex"
	"net/http"

	"github.com/luxfi/ids"
)

// Service provides RPC methods for the SessionVM
type Service struct {
	vm *VM
}

// CreateSessionArgs are the arguments for CreateSession
type CreateSessionArgs struct {
	Participants []string `json:"participants"`
	PublicKeys   []string `json:"publicKeys"` // Hex-encoded ML-KEM public keys
}

// CreateSessionReply is the reply for CreateSession
type CreateSessionReply struct {
	SessionID string `json:"sessionId"`
	Expires   int64  `json:"expires"`
}

// CreateSession creates a new encrypted session
func (s *Service) CreateSession(r *http.Request, args *CreateSessionArgs, reply *CreateSessionReply) error {
	participants := make([]ids.ID, len(args.Participants))
	for i, p := range args.Participants {
		id, err := ids.FromString(p)
		if err != nil {
			return err
		}
		participants[i] = id
	}

	publicKeys := make([][]byte, len(args.PublicKeys))
	for i, pk := range args.PublicKeys {
		key, err := hex.DecodeString(pk)
		if err != nil {
			return err
		}
		publicKeys[i] = key
	}

	session, err := s.vm.CreateSession(participants, publicKeys)
	if err != nil {
		return err
	}

	reply.SessionID = session.ID.String()
	reply.Expires = session.Expires.Unix()
	return nil
}

// GetSessionArgs are the arguments for GetSession
type GetSessionArgs struct {
	SessionID string `json:"sessionId"`
}

// GetSessionReply is the reply for GetSession
type GetSessionReply struct {
	Session *Session `json:"session"`
}

// GetSession returns session details
func (s *Service) GetSession(r *http.Request, args *GetSessionArgs, reply *GetSessionReply) error {
	sessionID, err := ids.FromString(args.SessionID)
	if err != nil {
		return err
	}

	session, err := s.vm.GetSession(sessionID)
	if err != nil {
		return err
	}

	reply.Session = session
	return nil
}

// SendMessageArgs are the arguments for SendMessage
type SendMessageArgs struct {
	SessionID  string `json:"sessionId"`
	Sender     string `json:"sender"`
	Ciphertext string `json:"ciphertext"` // Hex-encoded encrypted message
	Signature  string `json:"signature"`  // Hex-encoded ML-DSA signature
}

// SendMessageReply is the reply for SendMessage
type SendMessageReply struct {
	MessageID string `json:"messageId"`
	Sequence  uint64 `json:"sequence"`
}

// SendMessage sends an encrypted message within a session
func (s *Service) SendMessage(r *http.Request, args *SendMessageArgs, reply *SendMessageReply) error {
	sessionID, err := ids.FromString(args.SessionID)
	if err != nil {
		return err
	}

	sender, err := ids.FromString(args.Sender)
	if err != nil {
		return err
	}

	ciphertext, err := hex.DecodeString(args.Ciphertext)
	if err != nil {
		return err
	}

	signature, err := hex.DecodeString(args.Signature)
	if err != nil {
		return err
	}

	msg, err := s.vm.SendMessage(sessionID, sender, ciphertext, signature)
	if err != nil {
		return err
	}

	reply.MessageID = msg.ID.String()
	reply.Sequence = msg.Sequence
	return nil
}

// CloseSessionArgs are the arguments for CloseSession
type CloseSessionArgs struct {
	SessionID string `json:"sessionId"`
}

// CloseSessionReply is the reply for CloseSession
type CloseSessionReply struct {
	Success bool `json:"success"`
}

// CloseSession closes a session
func (s *Service) CloseSession(r *http.Request, args *CloseSessionArgs, reply *CloseSessionReply) error {
	sessionID, err := ids.FromString(args.SessionID)
	if err != nil {
		return err
	}

	if err := s.vm.CloseSession(sessionID); err != nil {
		return err
	}

	reply.Success = true
	return nil
}

// HealthArgs are the arguments for Health
type HealthArgs struct{}

// HealthReply is the reply for Health
type HealthReply struct {
	Healthy  bool `json:"healthy"`
	Sessions int  `json:"sessions"`
	Channels int  `json:"channels"`
	Pending  int  `json:"pending"`
}

// Health returns the health status
func (s *Service) Health(r *http.Request, args *HealthArgs, reply *HealthReply) error {
	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.Healthy = true
	reply.Sessions = len(s.vm.sessions)
	reply.Channels = len(s.vm.channels)
	reply.Pending = len(s.vm.pending)
	return nil
}
