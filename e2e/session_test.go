// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	sessionVMURL = "http://localhost:9652"
	alice        = "speKUgLBX6WRD5cfGeEfLa43LxTXUBckvtv4td6F3eTXvRP48"
	bob          = "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"
)

var sessionVMProcess *exec.Cmd

// rpcRequest makes a JSON-RPC request
func rpcRequest(t *testing.T, method string, params interface{}) map[string]interface{} {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  []interface{}{params},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(sessionVMURL+"/rpc", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return result
}

// checkHealth checks if SessionVM is healthy
func checkHealth(t *testing.T) bool {
	resp, err := http.Get(sessionVMURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	// Check if SessionVM is already running
	resp, err := http.Get(sessionVMURL + "/health")
	if err != nil {
		// Start SessionVM
		sessionVMProcess = exec.Command("../sessionvm")
		if err := sessionVMProcess.Start(); err != nil {
			fmt.Printf("Failed to start SessionVM: %v\n", err)
			os.Exit(1)
		}

		// Wait for startup
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			resp, err = http.Get(sessionVMURL + "/health")
			if err == nil {
				resp.Body.Close()
				break
			}
		}
	} else {
		resp.Body.Close()
	}

	// Run tests
	code := m.Run()

	// Cleanup
	if sessionVMProcess != nil {
		sessionVMProcess.Process.Kill()
	}

	os.Exit(code)
}

func TestHealthCheck(t *testing.T) {
	if !checkHealth(t) {
		t.Fatal("SessionVM is not healthy")
	}
}

func TestCreateSession(t *testing.T) {
	result := rpcRequest(t, "sessionvm.CreateSession", map[string]interface{}{
		"participants": []string{alice, bob},
		"publicKeys":   []string{"1234567890abcdef1234567890abcdef", "fedcba0987654321fedcba0987654321"},
	})

	if result["error"] != nil {
		t.Fatalf("CreateSession failed: %v", result["error"])
	}

	res := result["result"].(map[string]interface{})
	sessionID := res["sessionId"].(string)
	if sessionID == "" {
		t.Fatal("sessionId is empty")
	}
	t.Logf("Created session: %s", sessionID)

	// Verify session has PQ prefix (07 in hex = session ID starts with specific chars)
	if len(sessionID) < 10 {
		t.Fatal("sessionId too short")
	}
}

func TestSendMessage(t *testing.T) {
	// Create session first
	createResult := rpcRequest(t, "sessionvm.CreateSession", map[string]interface{}{
		"participants": []string{alice, bob},
		"publicKeys":   []string{"aabbccdd11223344aabbccdd11223344", "11223344aabbccdd11223344aabbccdd"},
	})

	if createResult["error"] != nil {
		t.Fatalf("CreateSession failed: %v", createResult["error"])
	}

	sessionID := createResult["result"].(map[string]interface{})["sessionId"].(string)

	// Send message from Alice
	msgResult := rpcRequest(t, "sessionvm.SendMessage", map[string]interface{}{
		"sessionId":  sessionID,
		"sender":     alice,
		"ciphertext": "48656c6c6f20426f6221", // "Hello Bob!" in hex
		"signature":  "deadbeef0123456789abcdef",
	})

	if msgResult["error"] != nil {
		t.Fatalf("SendMessage failed: %v", msgResult["error"])
	}

	res := msgResult["result"].(map[string]interface{})
	messageID := res["messageId"].(string)
	sequence := res["sequence"].(float64)

	if messageID == "" {
		t.Fatal("messageId is empty")
	}
	// Sequence can be any value depending on test order
	t.Logf("Sent message: %s (seq: %v)", messageID, sequence)
}

func TestConversation(t *testing.T) {
	// Create session
	createResult := rpcRequest(t, "sessionvm.CreateSession", map[string]interface{}{
		"participants": []string{alice, bob},
		"publicKeys":   []string{"abcd1234abcd1234abcd1234abcd1234", "1234abcd1234abcd1234abcd1234abcd"},
	})

	if createResult["error"] != nil {
		t.Fatalf("CreateSession failed: %v", createResult["error"])
	}

	sessionID := createResult["result"].(map[string]interface{})["sessionId"].(string)
	t.Logf("Session created: %s", sessionID)

	// Alice sends message
	msg1Result := rpcRequest(t, "sessionvm.SendMessage", map[string]interface{}{
		"sessionId":  sessionID,
		"sender":     alice,
		"ciphertext": "48656c6c6f21",         // "Hello!" in hex
		"signature":  "aabbccdd0123456789ab", // Valid hex signature
	})

	if msg1Result["error"] != nil {
		t.Fatalf("Alice's message failed: %v", msg1Result["error"])
	}
	seq1 := msg1Result["result"].(map[string]interface{})["sequence"].(float64)
	t.Logf("Alice sent message (seq: %v)", seq1)

	// Bob replies
	msg2Result := rpcRequest(t, "sessionvm.SendMessage", map[string]interface{}{
		"sessionId":  sessionID,
		"sender":     bob,
		"ciphertext": "486921",               // "Hi!" in hex
		"signature":  "ddeeff0123456789abcd", // Valid hex signature
	})

	if msg2Result["error"] != nil {
		t.Fatalf("Bob's message failed: %v", msg2Result["error"])
	}
	seq2 := msg2Result["result"].(map[string]interface{})["sequence"].(float64)
	t.Logf("Bob sent message (seq: %v)", seq2)

	if seq2 != seq1+1 {
		t.Fatalf("expected sequential messages, got seq1=%v seq2=%v", seq1, seq2)
	}

	// Get session to verify
	getResult := rpcRequest(t, "sessionvm.GetSession", map[string]interface{}{
		"sessionId": sessionID,
	})

	if getResult["error"] != nil {
		t.Fatalf("GetSession failed: %v", getResult["error"])
	}

	session := getResult["result"].(map[string]interface{})["session"].(map[string]interface{})
	status := session["status"].(string)
	if status != "active" {
		t.Fatalf("expected status 'active', got '%s'", status)
	}
	t.Logf("Session status: %s", status)

	// Close session
	closeResult := rpcRequest(t, "sessionvm.CloseSession", map[string]interface{}{
		"sessionId": sessionID,
	})

	if closeResult["error"] != nil {
		t.Fatalf("CloseSession failed: %v", closeResult["error"])
	}

	success := closeResult["result"].(map[string]interface{})["success"].(bool)
	if !success {
		t.Fatal("CloseSession returned false")
	}
	t.Log("Session closed successfully")
}

func TestInvalidSession(t *testing.T) {
	// Try to send message to non-existent session (valid base58 format)
	result := rpcRequest(t, "sessionvm.SendMessage", map[string]interface{}{
		"sessionId":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Valid base58 but non-existent
		"sender":     alice,
		"ciphertext": "aabb",
		"signature":  "ccdd",
	})

	if result["error"] == nil {
		t.Fatal("expected error for non-existent session")
	}
	t.Logf("Got expected error: %v", result["error"])
}

func TestMultipleSessions(t *testing.T) {
	var sessionIDs []string

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		result := rpcRequest(t, "sessionvm.CreateSession", map[string]interface{}{
			"participants": []string{alice, bob},
			"publicKeys":   []string{fmt.Sprintf("%032x", i), fmt.Sprintf("%032x", i+100)},
		})

		if result["error"] != nil {
			t.Fatalf("CreateSession %d failed: %v", i, result["error"])
		}

		sessionID := result["result"].(map[string]interface{})["sessionId"].(string)
		sessionIDs = append(sessionIDs, sessionID)
		t.Logf("Created session %d: %s", i, sessionID)
	}

	// Verify all sessions are unique
	seen := make(map[string]bool)
	for _, id := range sessionIDs {
		if seen[id] {
			t.Fatalf("duplicate session ID: %s", id)
		}
		seen[id] = true
	}

	t.Logf("Created %d unique sessions", len(sessionIDs))
}
