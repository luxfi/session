// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Verify session ID format: "07" + 64 hex chars = 66 chars
	if len(identity.SessionID) != 66 {
		t.Errorf("SessionID length = %d, want 66", len(identity.SessionID))
	}
	if !strings.HasPrefix(identity.SessionID, PQPrefix) {
		t.Errorf("SessionID prefix = %s, want %s", identity.SessionID[:2], PQPrefix)
	}

	// Verify key sizes
	if len(identity.KEMPublicKey) != MLKEMPublicKeySize {
		t.Errorf("KEMPublicKey size = %d, want %d", len(identity.KEMPublicKey), MLKEMPublicKeySize)
	}
	if len(identity.KEMSecretKey) != MLKEMSecretKeySize {
		t.Errorf("KEMSecretKey size = %d, want %d", len(identity.KEMSecretKey), MLKEMSecretKeySize)
	}
	if len(identity.DSAPublicKey) != MLDSAPublicKeySize {
		t.Errorf("DSAPublicKey size = %d, want %d", len(identity.DSAPublicKey), MLDSAPublicKeySize)
	}
	if len(identity.DSASecretKey) != MLDSASecretKeySize {
		t.Errorf("DSASecretKey size = %d, want %d", len(identity.DSASecretKey), MLDSASecretKeySize)
	}
}

func TestDeriveSessionID(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Derive session ID from public keys
	derivedID, err := DeriveSessionID(identity.KEMPublicKey, identity.DSAPublicKey)
	if err != nil {
		t.Fatalf("DeriveSessionID failed: %v", err)
	}

	// Should match the identity's session ID
	if derivedID != identity.SessionID {
		t.Errorf("Derived ID = %s, want %s", derivedID, identity.SessionID)
	}
}

func TestDeriveSessionIDInvalidInput(t *testing.T) {
	// Invalid KEM public key size
	_, err := DeriveSessionID(make([]byte, 100), make([]byte, MLDSAPublicKeySize))
	if err != ErrInvalidPublicKey {
		t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
	}

	// Invalid DSA public key size
	_, err = DeriveSessionID(make([]byte, MLKEMPublicKeySize), make([]byte, 100))
	if err != ErrInvalidPublicKey {
		t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Encapsulate using recipient's public key
	ciphertext, sharedSecret1, err := Encapsulate(identity.KEMPublicKey)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Verify sizes
	if len(ciphertext) != MLKEMCiphertextSize {
		t.Errorf("Ciphertext size = %d, want %d", len(ciphertext), MLKEMCiphertextSize)
	}
	if len(sharedSecret1) != MLKEMSharedKeySize {
		t.Errorf("SharedSecret size = %d, want %d", len(sharedSecret1), MLKEMSharedKeySize)
	}

	// Decapsulate using recipient's secret key
	sharedSecret2, err := Decapsulate(identity.KEMSecretKey, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Shared secrets do not match")
	}
}

func TestEncapsulateInvalidPublicKey(t *testing.T) {
	_, _, err := Encapsulate(make([]byte, 100))
	if err != ErrInvalidPublicKey {
		t.Errorf("Expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestDecapsulateInvalidInput(t *testing.T) {
	identity, _ := GenerateIdentity()

	// Invalid secret key size
	_, err := Decapsulate(make([]byte, 100), make([]byte, MLKEMCiphertextSize))
	if err != ErrInvalidSecretKey {
		t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
	}

	// Invalid ciphertext size
	_, err = Decapsulate(identity.KEMSecretKey, make([]byte, 100))
	if err != ErrInvalidCiphertext {
		t.Errorf("Expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestSignVerify(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	message := []byte("Hello, post-quantum world!")

	// Sign
	signature, err := Sign(identity.DSASecretKey, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature size
	if len(signature) != MLDSASignatureSize {
		t.Errorf("Signature size = %d, want %d", len(signature), MLDSASignatureSize)
	}

	// Verify signature
	if !Verify(identity.DSAPublicKey, message, signature) {
		t.Error("Signature verification failed")
	}

	// Verify with wrong message should fail
	if Verify(identity.DSAPublicKey, []byte("wrong message"), signature) {
		t.Error("Signature verification should have failed with wrong message")
	}

	// Verify with wrong public key should fail
	otherIdentity, _ := GenerateIdentity()
	if Verify(otherIdentity.DSAPublicKey, message, signature) {
		t.Error("Signature verification should have failed with wrong public key")
	}
}

func TestSignInvalidSecretKey(t *testing.T) {
	_, err := Sign(make([]byte, 100), []byte("message"))
	if err != ErrInvalidSecretKey {
		t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
	}
}

func TestVerifyInvalidInput(t *testing.T) {
	identity, _ := GenerateIdentity()
	message := []byte("test")
	signature := make([]byte, MLDSASignatureSize)

	// Invalid public key size
	if Verify(make([]byte, 100), message, signature) {
		t.Error("Verify should return false for invalid public key")
	}

	// Invalid signature size
	if Verify(identity.DSAPublicKey, message, make([]byte, 100)) {
		t.Error("Verify should return false for invalid signature")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("Secret message for encryption test")

	// Encrypt
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext")
	}

	// Decrypt
	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text does not match original")
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Too short ciphertext
	_, err := Decrypt(key, make([]byte, 10))
	if err != ErrInvalidCiphertext {
		t.Errorf("Expected ErrInvalidCiphertext, got %v", err)
	}

	// Corrupted ciphertext
	ciphertext, _ := Encrypt(key, []byte("test"))
	ciphertext[len(ciphertext)-1] ^= 0xFF // Flip bits in tag
	_, err = Decrypt(key, ciphertext)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got %v", err)
	}
}

func TestEncryptToRecipientDecryptFromSender(t *testing.T) {
	// Generate two identities
	alice, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity (Alice) failed: %v", err)
	}

	bob, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity (Bob) failed: %v", err)
	}

	// Alice encrypts message to Bob
	plaintext := []byte("Hello Bob, this is a secret message from Alice!")
	ciphertext, err := EncryptToRecipient(bob.KEMPublicKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptToRecipient failed: %v", err)
	}

	// Bob decrypts message
	decrypted, err := DecryptFromSender(bob.KEMSecretKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptFromSender failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted message does not match original")
	}

	// Alice should not be able to decrypt Bob's message
	_, err = DecryptFromSender(alice.KEMSecretKey, ciphertext)
	if err == nil {
		t.Error("Alice should not be able to decrypt message meant for Bob")
	}
}

func TestIdentitySignMessage(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	message := []byte("Message to sign")

	// Sign message
	signedMessage, err := identity.SignMessage(message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	// Should be signature + message
	expectedLen := MLDSASignatureSize + len(message)
	if len(signedMessage) != expectedLen {
		t.Errorf("SignedMessage length = %d, want %d", len(signedMessage), expectedLen)
	}

	// Verify message
	recoveredMessage, valid := identity.VerifyMessage(signedMessage)
	if !valid {
		t.Error("VerifyMessage returned false for valid signature")
	}
	if !bytes.Equal(message, recoveredMessage) {
		t.Error("Recovered message does not match original")
	}
}

func TestIdentityVerifyMessageInvalid(t *testing.T) {
	identity, _ := GenerateIdentity()

	// Too short
	_, valid := identity.VerifyMessage(make([]byte, 100))
	if valid {
		t.Error("VerifyMessage should return false for too short input")
	}

	// Corrupted signature
	message := []byte("test")
	signedMessage, _ := identity.SignMessage(message)
	signedMessage[0] ^= 0xFF // Corrupt signature
	_, valid = identity.VerifyMessage(signedMessage)
	if valid {
		t.Error("VerifyMessage should return false for corrupted signature")
	}
}

func TestIdentityEncryptTo(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	message := []byte("Encrypted via EncryptTo method")

	ciphertext, err := alice.EncryptTo(bob, message)
	if err != nil {
		t.Fatalf("EncryptTo failed: %v", err)
	}

	decrypted, err := bob.DecryptFrom(ciphertext)
	if err != nil {
		t.Fatalf("DecryptFrom failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Error("Decrypted message does not match original")
	}
}

func TestPublicIdentity(t *testing.T) {
	identity, _ := GenerateIdentity()
	pubIdentity := identity.PublicIdentity()

	// Should have same session ID and public keys
	if pubIdentity.SessionID != identity.SessionID {
		t.Error("SessionID mismatch")
	}
	if !bytes.Equal(pubIdentity.KEMPublicKey, identity.KEMPublicKey) {
		t.Error("KEMPublicKey mismatch")
	}
	if !bytes.Equal(pubIdentity.DSAPublicKey, identity.DSAPublicKey) {
		t.Error("DSAPublicKey mismatch")
	}

	// Should NOT have secret keys
	if len(pubIdentity.KEMSecretKey) != 0 {
		t.Error("PublicIdentity should not have KEMSecretKey")
	}
	if len(pubIdentity.DSASecretKey) != 0 {
		t.Error("PublicIdentity should not have DSASecretKey")
	}
}

func TestUniqueIdentities(t *testing.T) {
	// Generate multiple identities and ensure they're unique
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		identity, err := GenerateIdentity()
		if err != nil {
			t.Fatalf("GenerateIdentity failed: %v", err)
		}
		if ids[identity.SessionID] {
			t.Error("Duplicate session ID generated")
		}
		ids[identity.SessionID] = true
	}
}

func TestSessionIDHexFormat(t *testing.T) {
	identity, _ := GenerateIdentity()

	// Remove prefix and verify it's valid hex
	hexPart := identity.SessionID[2:]
	_, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Errorf("SessionID hex part is not valid hex: %v", err)
	}
}

func BenchmarkGenerateIdentity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateIdentity()
		if err != nil {
			b.Fatalf("GenerateIdentity failed: %v", err)
		}
	}
}

func BenchmarkEncapsulateDecapsulate(b *testing.B) {
	identity, _ := GenerateIdentity()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ct, ss, err := Encapsulate(identity.KEMPublicKey)
		if err != nil {
			b.Fatalf("Encapsulate failed: %v", err)
		}
		_, err = Decapsulate(identity.KEMSecretKey, ct)
		if err != nil {
			b.Fatalf("Decapsulate failed: %v", err)
		}
		_ = ss
	}
}

func BenchmarkSignVerify(b *testing.B) {
	identity, _ := GenerateIdentity()
	message := []byte("Benchmark message for signing")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig, err := Sign(identity.DSASecretKey, message)
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
		if !Verify(identity.DSAPublicKey, message, sig) {
			b.Fatal("Verify failed")
		}
	}
}

func BenchmarkEncryptToRecipient(b *testing.B) {
	identity, _ := GenerateIdentity()
	message := []byte("Benchmark message for encryption - this is a longer message to test throughput")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ct, err := EncryptToRecipient(identity.KEMPublicKey, message)
		if err != nil {
			b.Fatalf("EncryptToRecipient failed: %v", err)
		}
		_, err = DecryptFromSender(identity.KEMSecretKey, ct)
		if err != nil {
			b.Fatalf("DecryptFromSender failed: %v", err)
		}
	}
}
