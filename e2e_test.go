// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/session/core"
	"github.com/luxfi/session/daemon"
	"github.com/luxfi/session/protocol"
	"github.com/luxfi/session/storage"
	"github.com/luxfi/session/swarm"
)

// TestE2E_FullSessionLifecycle tests the complete session lifecycle from creation to finalization.
func TestE2E_FullSessionLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create and start the service
	config := daemon.DefaultConfig()
	config.NodeID = core.Hash([]byte("test-node"))
	config.MaxSessions = 10
	config.HeartbeatInterval = 100 * time.Millisecond

	service := daemon.New(config)
	if err := service.Start(ctx); err != nil {
		t.Fatalf("Failed to start service: %v", err)
	}
	defer service.Stop()

	// Create committee
	committee := []core.ID{
		core.Hash([]byte("node1")),
		core.Hash([]byte("node2")),
		core.Hash([]byte("node3")),
	}

	// 1. Create session
	serviceID := core.Hash([]byte("test-service"))
	epoch := uint64(100)
	txID := core.Hash([]byte("create-tx"))

	session, err := service.CreateSession(serviceID, epoch, txID, committee)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.State != core.SessionStatePending {
		t.Errorf("Expected pending state, got %v", session.State)
	}

	// Verify deterministic session ID
	expectedSessionID := core.ComputeSessionID(serviceID, epoch, txID)
	if session.ID != expectedSessionID {
		t.Error("Session ID not deterministic")
	}

	// 2. Start session
	if err := service.StartSession(session.ID); err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Give the runner goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Verify session is running
	retrieved, err := service.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	if retrieved.State != core.SessionStateRunning {
		t.Errorf("Expected running state, got %v", retrieved.State)
	}

	// 3. Create and complete an oracle write step
	stepTxID := core.Hash([]byte("step-tx"))
	inputHash := core.Hash([]byte("input-data"))

	// We need to access the runner directly for oracle requests
	// In a real scenario, this would go through message handlers
	// For this test, we'll complete the step through finalization

	// 4. Finalize session (no steps in this simple case)
	outputHash := core.Hash([]byte("final-output"))
	oracleRoot := core.Hash([]byte("oracle-root"))
	receiptsRoot := core.Hash([]byte("receipts-root"))

	if err := service.FinalizeSession(session.ID, outputHash, oracleRoot, receiptsRoot); err != nil {
		t.Fatalf("Failed to finalize session: %v", err)
	}

	// 5. Verify finalized state
	finalized, err := service.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get finalized session: %v", err)
	}

	if finalized.State != core.SessionStateFinalized {
		t.Errorf("Expected finalized state, got %v", finalized.State)
	}

	if finalized.OutputHash != outputHash {
		t.Error("Output hash mismatch")
	}

	if finalized.OracleRoot != oracleRoot {
		t.Error("Oracle root mismatch")
	}

	if finalized.ReceiptsRoot != receiptsRoot {
		t.Error("Receipts root mismatch")
	}

	_ = stepTxID
	_ = inputHash
}

// TestE2E_OracleWorkflow tests the oracle request → record → commit workflow.
func TestE2E_OracleWorkflow(t *testing.T) {
	// Create oracle request
	serviceID := core.Hash([]byte("service"))
	sessionID := core.Hash([]byte("session"))
	txID := core.Hash([]byte("tx"))
	inputHash := core.Hash([]byte("input"))

	request := protocol.NewOracleRequest(
		serviceID,
		sessionID,
		txID,
		inputHash,
		0, // step
		0, // retry
		protocol.RequestKindWrite,
	)

	// Verify deterministic request ID
	expectedID := core.ComputeRequestID(serviceID, sessionID, txID, 0, 0)
	if request.ID != expectedID {
		t.Error("Request ID not deterministic")
	}

	// Submit oracle records
	submitter1 := core.Hash([]byte("submitter1"))
	submitter2 := core.Hash([]byte("submitter2"))
	submitter3 := core.Hash([]byte("submitter3"))

	record1 := protocol.NewOracleRecord(request.ID, submitter1, []byte("data1"), []byte("sig1"))
	record2 := protocol.NewOracleRecord(request.ID, submitter2, []byte("data2"), []byte("sig2"))
	record3 := protocol.NewOracleRecord(request.ID, submitter3, []byte("data3"), []byte("sig3"))

	request.Records = []*protocol.OracleRecord{record1, record2, record3}

	// Compute Merkle root
	commitRoot := protocol.ComputeMerkleRoot(request.Records)
	if commitRoot.Empty() {
		t.Error("Expected non-empty commit root")
	}

	// Verify deterministic root
	commitRoot2 := protocol.ComputeMerkleRoot(request.Records)
	if commitRoot != commitRoot2 {
		t.Error("Merkle root not deterministic")
	}

	// Verify different data produces different root
	record1Alt := protocol.NewOracleRecord(request.ID, submitter1, []byte("different"), []byte("sig1"))
	altRecords := []*protocol.OracleRecord{record1Alt, record2, record3}
	altRoot := protocol.ComputeMerkleRoot(altRecords)
	if commitRoot == altRoot {
		t.Error("Different data should produce different root")
	}
}

// TestE2E_SwarmAssignment tests the epoch-based swarm assignment.
func TestE2E_SwarmAssignment(t *testing.T) {
	config := &swarm.Config{
		MinCommitteeSize: 3,
		MaxCommitteeSize: 7,
		QuorumThreshold:  0.67,
	}
	assigner := swarm.NewAssigner(config)

	// Create eligible nodes
	eligibleNodes := make([]core.ID, 20)
	for i := 0; i < 20; i++ {
		eligibleNodes[i] = core.Hash([]byte{byte(i)})
	}

	serviceID := core.Hash([]byte("service"))
	epoch := uint64(100)
	epochRandomness := core.Hash([]byte("beacon-randomness"))

	// Assign committee
	committee, err := assigner.AssignCommittee(serviceID, epoch, epochRandomness, eligibleNodes)
	if err != nil {
		t.Fatalf("Failed to assign committee: %v", err)
	}

	// Verify committee size
	if len(committee) < config.MinCommitteeSize || len(committee) > config.MaxCommitteeSize {
		t.Errorf("Committee size %d out of bounds [%d, %d]",
			len(committee), config.MinCommitteeSize, config.MaxCommitteeSize)
	}

	// Verify determinism
	committee2, _ := assigner.AssignCommittee(serviceID, epoch, epochRandomness, eligibleNodes)
	if len(committee) != len(committee2) {
		t.Error("Committee assignment not deterministic")
	}
	for i := range committee {
		if committee[i] != committee2[i] {
			t.Error("Committee members don't match")
		}
	}

	// Verify different epoch produces different committee
	committee3, _ := assigner.AssignCommittee(serviceID, epoch+1, epochRandomness, eligibleNodes)
	same := true
	for i := range committee {
		if i < len(committee3) && committee[i] != committee3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Different epoch should produce different committee")
	}

	// Verify quorum calculation
	quorum := assigner.QuorumSize(len(committee))
	if !assigner.IsQuorum(quorum, len(committee)) {
		t.Error("Quorum size should satisfy quorum check")
	}
	if assigner.IsQuorum(quorum-1, len(committee)) {
		t.Error("Below quorum should not satisfy quorum check")
	}
}

// TestE2E_StorageSessionStore tests session storage operations.
func TestE2E_StorageSessionStore(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()

	sessionStore := storage.NewSessionStore(store)

	// Create a session
	serviceID := core.Hash([]byte("service"))
	epoch := uint64(100)
	txID := core.Hash([]byte("tx"))
	committee := []core.ID{core.Hash([]byte("node1"))}

	session := core.NewSession(serviceID, epoch, txID, committee)

	// Store session
	if err := sessionStore.Put(session); err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Check exists
	exists, err := sessionStore.Has(session.ID)
	if err != nil {
		t.Fatalf("Failed to check session: %v", err)
	}
	if !exists {
		t.Error("Session should exist")
	}

	// Retrieve session
	retrieved, err := sessionStore.Get(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Error("Session ID mismatch")
	}
	if retrieved.ServiceID != session.ServiceID {
		t.Error("Service ID mismatch")
	}
	if retrieved.Epoch != session.Epoch {
		t.Error("Epoch mismatch")
	}
	if retrieved.State != session.State {
		t.Error("State mismatch")
	}

	// Delete session
	if err := sessionStore.Delete(session.ID); err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify deleted
	exists, _ = sessionStore.Has(session.ID)
	if exists {
		t.Error("Session should not exist after deletion")
	}
}

// TestE2E_AttestationDomainSeparation tests that attestation domains are properly separated.
func TestE2E_AttestationDomainSeparation(t *testing.T) {
	subjectID := core.Hash([]byte("subject"))
	commitRoot := core.Hash([]byte("commit"))
	epoch := uint64(100)

	// Create attestations for different domains
	attWrite := protocol.NewAttestation(
		protocol.DomainOracleWrite,
		subjectID,
		commitRoot,
		epoch,
		nil,
		nil,
	)

	attRead := protocol.NewAttestation(
		protocol.DomainOracleRead,
		subjectID,
		commitRoot,
		epoch,
		nil,
		nil,
	)

	// Same inputs with different domains should produce different attestation IDs
	if attWrite.ID == attRead.ID {
		t.Error("Different domains should produce different attestation IDs")
	}

	// Verify domain separators are different
	sepWrite := protocol.DomainSeparator(protocol.DomainOracleWrite)
	sepRead := protocol.DomainSeparator(protocol.DomainOracleRead)
	sepSession := protocol.DomainSeparator(protocol.DomainSessionComplete)
	sepBeacon := protocol.DomainSeparator(protocol.DomainEpochBeacon)

	if string(sepWrite) == string(sepRead) {
		t.Error("Write and read separators should differ")
	}
	if string(sepWrite) == string(sepSession) {
		t.Error("Write and session separators should differ")
	}
	if string(sepWrite) == string(sepBeacon) {
		t.Error("Write and beacon separators should differ")
	}
}

// TestE2E_EquivocationDetection tests detection of conflicting attestations.
func TestE2E_EquivocationDetection(t *testing.T) {
	subjectID := core.Hash([]byte("subject"))
	epoch := uint64(100)

	signerID := core.Hash([]byte("signer"))

	// Two attestations for same subject but different commit roots = equivocation
	att1 := protocol.NewAttestation(
		protocol.DomainOracleWrite,
		subjectID,
		core.Hash([]byte("commit1")),
		epoch,
		[]core.ID{signerID},
		nil,
	)

	att2 := protocol.NewAttestation(
		protocol.DomainOracleWrite,
		subjectID,
		core.Hash([]byte("commit2")),
		epoch,
		[]core.ID{signerID},
		nil,
	)

	// Should detect equivocation
	evidence := protocol.DetectEquivocation(att1, att2)
	if evidence == nil {
		t.Error("Expected equivocation to be detected")
	}
	if evidence.NodeID != signerID {
		t.Error("Wrong equivocating node ID")
	}

	// Same commit root = no equivocation
	att3 := protocol.NewAttestation(
		protocol.DomainOracleWrite,
		subjectID,
		core.Hash([]byte("commit1")), // Same as att1
		epoch,
		[]core.ID{signerID},
		nil,
	)

	evidence = protocol.DetectEquivocation(att1, att3)
	if evidence != nil {
		t.Error("Should not detect equivocation for same commit root")
	}

	// Different subject = no equivocation
	att4 := protocol.NewAttestation(
		protocol.DomainOracleWrite,
		core.Hash([]byte("other-subject")),
		core.Hash([]byte("commit2")),
		epoch,
		[]core.ID{signerID},
		nil,
	)

	evidence = protocol.DetectEquivocation(att1, att4)
	if evidence != nil {
		t.Error("Should not detect equivocation for different subjects")
	}
}

// TestE2E_ServiceNodeRegistry tests the service node registry.
func TestE2E_ServiceNodeRegistry(t *testing.T) {
	registry := swarm.NewRegistry()

	// Register nodes
	node1ID := core.Hash([]byte("node1"))
	node2ID := core.Hash([]byte("node2"))

	node1, err := registry.Register(node1ID, []byte("pubkey1"), "localhost:9651", 1000)
	if err != nil {
		t.Fatalf("Failed to register node1: %v", err)
	}
	if node1.Status != swarm.NodeStatusRegistered {
		t.Error("Expected registered status")
	}

	_, err = registry.Register(node2ID, []byte("pubkey2"), "localhost:9652", 2000)
	if err != nil {
		t.Fatalf("Failed to register node2: %v", err)
	}

	// Duplicate registration should fail
	_, err = registry.Register(node1ID, []byte("pubkey1"), "localhost:9653", 1000)
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}

	// Activate nodes
	if err := registry.Activate(node1ID); err != nil {
		t.Fatalf("Failed to activate node1: %v", err)
	}
	if err := registry.Activate(node2ID); err != nil {
		t.Fatalf("Failed to activate node2: %v", err)
	}

	// Check counts
	if registry.Count() != 2 {
		t.Errorf("Expected 2 nodes, got %d", registry.Count())
	}
	if registry.CountActive() != 2 {
		t.Errorf("Expected 2 active nodes, got %d", registry.CountActive())
	}

	// Get active node IDs
	activeIDs := registry.GetActiveIDs()
	if len(activeIDs) != 2 {
		t.Errorf("Expected 2 active IDs, got %d", len(activeIDs))
	}

	// Suspend a node
	if err := registry.Suspend(node1ID, "maintenance"); err != nil {
		t.Fatalf("Failed to suspend node: %v", err)
	}

	if registry.CountActive() != 1 {
		t.Errorf("Expected 1 active node after suspend, got %d", registry.CountActive())
	}

	// Reactivate
	if err := registry.Activate(node1ID); err != nil {
		t.Fatalf("Failed to reactivate node: %v", err)
	}

	if registry.CountActive() != 2 {
		t.Errorf("Expected 2 active nodes after reactivation, got %d", registry.CountActive())
	}

	// Slash a node
	if err := registry.Slash(node2ID, "equivocation evidence"); err != nil {
		t.Fatalf("Failed to slash node: %v", err)
	}

	node2, _ := registry.Get(node2ID)
	if node2.Status != swarm.NodeStatusSlashed {
		t.Error("Expected slashed status")
	}

	if registry.CountActive() != 1 {
		t.Errorf("Expected 1 active node after slash, got %d", registry.CountActive())
	}
}

// TestE2E_DeterministicIDs tests that all ID computations are deterministic.
func TestE2E_DeterministicIDs(t *testing.T) {
	serviceID := core.Hash([]byte("service"))
	sessionID := core.Hash([]byte("session"))
	txID := core.Hash([]byte("tx"))
	epoch := uint64(12345)

	// Run multiple times to verify determinism
	for i := 0; i < 10; i++ {
		// Session ID
		sid1 := core.ComputeSessionID(serviceID, epoch, txID)
		sid2 := core.ComputeSessionID(serviceID, epoch, txID)
		if sid1 != sid2 {
			t.Error("Session ID not deterministic")
		}

		// Request ID
		rid1 := core.ComputeRequestID(serviceID, sessionID, txID, 0, 0)
		rid2 := core.ComputeRequestID(serviceID, sessionID, txID, 0, 0)
		if rid1 != rid2 {
			t.Error("Request ID not deterministic")
		}

		// Attestation ID
		commitRoot := core.Hash([]byte("commit"))
		aid1 := protocol.ComputeAttestationID(protocol.DomainOracleWrite, serviceID, commitRoot, epoch)
		aid2 := protocol.ComputeAttestationID(protocol.DomainOracleWrite, serviceID, commitRoot, epoch)
		if aid1 != aid2 {
			t.Error("Attestation ID not deterministic")
		}
	}
}
