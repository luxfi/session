// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

func newTestVM(t *testing.T) *VM {
	t.Helper()
	logger := log.NewWriter(io.Discard)
	factory := &Factory{}
	vm, err := factory.New(logger)
	if err != nil {
		t.Fatalf("Failed to create VM: %v", err)
	}
	return vm
}

func TestVMInitialize(t *testing.T) {
	vm := newTestVM(t)

	if vm.sessions == nil {
		t.Error("sessions map should be initialized")
	}
	if vm.messages == nil {
		t.Error("messages map should be initialized")
	}
	if vm.channels == nil {
		t.Error("channels map should be initialized")
	}
	if vm.config.IDPrefix != "07" {
		t.Errorf("IDPrefix = %s, want 07", vm.config.IDPrefix)
	}
}

func TestVMShutdown(t *testing.T) {
	vm := newTestVM(t)
	ctx := context.Background()

	err := vm.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestCreateSession(t *testing.T) {
	vm := newTestVM(t)

	participant1 := ids.GenerateTestID()
	participant2 := ids.GenerateTestID()
	participants := []ids.ID{participant1, participant2}

	publicKey1 := make([]byte, 1184) // ML-KEM-768 public key size
	publicKey2 := make([]byte, 1184)
	publicKeys := [][]byte{publicKey1, publicKey2}

	session, err := vm.CreateSession(participants, publicKeys)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if session.Status != SessionActive {
		t.Errorf("Session status = %s, want %s", session.Status, SessionActive)
	}
	if len(session.Participants) != 2 {
		t.Errorf("Participants count = %d, want 2", len(session.Participants))
	}
	if session.Expires.Before(time.Now()) {
		t.Error("Session should not be expired immediately")
	}
}

func TestGetSession(t *testing.T) {
	vm := newTestVM(t)

	participants := []ids.ID{ids.GenerateTestID()}
	session, _ := vm.CreateSession(participants, nil)

	// Get existing session
	retrieved, err := vm.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if retrieved.ID != session.ID {
		t.Error("Retrieved session ID mismatch")
	}

	// Get non-existent session
	_, err = vm.GetSession(ids.GenerateTestID())
	if err != errUnknownSession {
		t.Errorf("Expected errUnknownSession, got %v", err)
	}
}

func TestSendMessage(t *testing.T) {
	vm := newTestVM(t)

	participant := ids.GenerateTestID()
	participants := []ids.ID{participant}
	session, _ := vm.CreateSession(participants, nil)

	ciphertext := []byte("encrypted message")
	signature := []byte("signature")

	msg, err := vm.SendMessage(session.ID, participant, ciphertext, signature)
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	if msg.SessionID != session.ID {
		t.Error("Message session ID mismatch")
	}
	if msg.Sender != participant {
		t.Error("Message sender mismatch")
	}
	if string(msg.Ciphertext) != string(ciphertext) {
		t.Error("Message ciphertext mismatch")
	}
}

func TestSendMessageUnauthorized(t *testing.T) {
	vm := newTestVM(t)

	participant := ids.GenerateTestID()
	unauthorized := ids.GenerateTestID()
	participants := []ids.ID{participant}
	session, _ := vm.CreateSession(participants, nil)

	_, err := vm.SendMessage(session.ID, unauthorized, []byte("msg"), []byte("sig"))
	if err != errUnauthorized {
		t.Errorf("Expected errUnauthorized, got %v", err)
	}
}

func TestSendMessageToClosedSession(t *testing.T) {
	vm := newTestVM(t)

	participant := ids.GenerateTestID()
	session, _ := vm.CreateSession([]ids.ID{participant}, nil)

	vm.CloseSession(session.ID)

	_, err := vm.SendMessage(session.ID, participant, []byte("msg"), []byte("sig"))
	if err != errSessionClosed {
		t.Errorf("Expected errSessionClosed, got %v", err)
	}
}

func TestCloseSession(t *testing.T) {
	vm := newTestVM(t)

	session, _ := vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)

	err := vm.CloseSession(session.ID)
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	retrieved, _ := vm.GetSession(session.ID)
	if retrieved.Status != SessionClosed {
		t.Errorf("Session status = %s, want %s", retrieved.Status, SessionClosed)
	}
}

func TestCloseNonExistentSession(t *testing.T) {
	vm := newTestVM(t)

	err := vm.CloseSession(ids.GenerateTestID())
	if err != errUnknownSession {
		t.Errorf("Expected errUnknownSession, got %v", err)
	}
}

func TestHealthCheck(t *testing.T) {
	vm := newTestVM(t)
	ctx := context.Background()

	// Create some sessions
	vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)
	vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)

	result, err := vm.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	health, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("HealthCheck should return map")
	}

	healthy, _ := health["healthy"].(bool)
	if !healthy {
		t.Error("VM should be healthy")
	}

	sessions, _ := health["sessions"].(int)
	if sessions != 2 {
		t.Errorf("Sessions count = %d, want 2", sessions)
	}
}

func TestCreateHandlers(t *testing.T) {
	vm := newTestVM(t)
	ctx := context.Background()

	handlers, err := vm.CreateHandlers(ctx)
	if err != nil {
		t.Fatalf("CreateHandlers failed: %v", err)
	}

	if handlers["/rpc"] == nil {
		t.Error("RPC handler should be registered")
	}
}

func TestMultipleSessions(t *testing.T) {
	vm := newTestVM(t)

	sessions := make([]*Session, 10)
	for i := 0; i < 10; i++ {
		session, err := vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)
		if err != nil {
			t.Fatalf("CreateSession %d failed: %v", i, err)
		}
		sessions[i] = session
	}

	// Verify all sessions exist
	for i, session := range sessions {
		retrieved, err := vm.GetSession(session.ID)
		if err != nil {
			t.Errorf("GetSession %d failed: %v", i, err)
		}
		if retrieved.ID != session.ID {
			t.Errorf("Session %d ID mismatch", i)
		}
	}
}

func TestMessageSequencing(t *testing.T) {
	vm := newTestVM(t)

	participant := ids.GenerateTestID()
	session, _ := vm.CreateSession([]ids.ID{participant}, nil)

	// Send multiple messages
	for i := 0; i < 5; i++ {
		msg, err := vm.SendMessage(session.ID, participant, []byte("msg"), []byte("sig"))
		if err != nil {
			t.Fatalf("SendMessage %d failed: %v", i, err)
		}
		if msg.Sequence != uint64(i) {
			t.Errorf("Message %d sequence = %d, want %d", i, msg.Sequence, i)
		}
	}
}

func TestSessionIDGeneration(t *testing.T) {
	vm := newTestVM(t)

	// Create sessions and verify IDs are unique
	seenIDs := make(map[ids.ID]bool)
	for i := 0; i < 100; i++ {
		session, err := vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		if seenIDs[session.ID] {
			t.Error("Duplicate session ID generated")
		}
		seenIDs[session.ID] = true
	}
}

func TestVMIDAndName(t *testing.T) {
	if Name != "sessionvm" {
		t.Errorf("Name = %s, want sessionvm", Name)
	}

	// Verify VMID is properly set
	expectedPrefix := []byte{'s', 'e', 's', 's', 'i', 'o', 'n', 'v', 'm'}
	for i, b := range expectedPrefix {
		if VMID[i] != b {
			t.Errorf("VMID[%d] = %d, want %d", i, VMID[i], b)
		}
	}
}

func BenchmarkCreateSession(b *testing.B) {
	logger := log.NewWriter(io.Discard)
	factory := &Factory{}
	vm, _ := factory.New(logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)
		if err != nil {
			b.Fatalf("CreateSession failed: %v", err)
		}
	}
}

func BenchmarkSendMessage(b *testing.B) {
	logger := log.NewWriter(io.Discard)
	factory := &Factory{}
	vm, _ := factory.New(logger)

	participant := ids.GenerateTestID()
	session, _ := vm.CreateSession([]ids.ID{participant}, nil)
	ciphertext := make([]byte, 1024)
	signature := make([]byte, 3309)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := vm.SendMessage(session.ID, participant, ciphertext, signature)
		if err != nil {
			b.Fatalf("SendMessage failed: %v", err)
		}
	}
}

func BenchmarkGetSession(b *testing.B) {
	logger := log.NewWriter(io.Discard)
	factory := &Factory{}
	vm, _ := factory.New(logger)

	session, _ := vm.CreateSession([]ids.ID{ids.GenerateTestID()}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := vm.GetSession(session.ID)
		if err != nil {
			b.Fatalf("GetSession failed: %v", err)
		}
	}
}
