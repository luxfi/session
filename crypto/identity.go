// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package crypto provides post-quantum cryptographic operations for SessionVM
// using github.com/luxfi/crypto for ML-KEM-768 and ML-DSA-65.
package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/blake2b"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/mlkem"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// PQ Session ID prefix (07 = post-quantum)
	PQPrefix = "07"

	// Legacy Session ID prefix (05 = X25519/Ed25519)
	LegacyPrefix = "05"

	// ML-KEM-768 sizes (NIST Level 3, FIPS 203)
	MLKEMPublicKeySize  = mlkem.MLKEM768PublicKeySize
	MLKEMSecretKeySize  = mlkem.MLKEM768PrivateKeySize
	MLKEMCiphertextSize = mlkem.MLKEM768CiphertextSize
	MLKEMSharedKeySize  = mlkem.MLKEM768SharedKeySize

	// ML-DSA-65 sizes (NIST Level 3, FIPS 204)
	MLDSAPublicKeySize = mldsa.MLDSA65PublicKeySize
	MLDSASecretKeySize = mldsa.MLDSA65PrivateKeySize
	MLDSASignatureSize = mldsa.MLDSA65SignatureSize
)

var (
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidSecretKey  = errors.New("invalid secret key")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// Identity represents a post-quantum identity for the Session network
type Identity struct {
	// Session ID: "07" + hex(Blake2b-256(KEM_pk || DSA_pk))
	SessionID string `json:"sessionId"`

	// ML-KEM-768 keypair (for receiving encrypted messages)
	KEMPublicKey []byte `json:"kemPublicKey"`
	KEMSecretKey []byte `json:"kemSecretKey,omitempty"`

	// ML-DSA-65 keypair (for signing messages)
	DSAPublicKey []byte `json:"dsaPublicKey"`
	DSASecretKey []byte `json:"dsaSecretKey,omitempty"`

	// Internal key objects for operations
	kemPublicKeyObj  *mlkem.PublicKey
	kemPrivateKeyObj *mlkem.PrivateKey
	dsaPublicKeyObj  *mldsa.PublicKey
	dsaPrivateKeyObj *mldsa.PrivateKey
}

// PublicIdentity returns only the public parts of the identity
func (i *Identity) PublicIdentity() *Identity {
	pub := &Identity{
		SessionID:    i.SessionID,
		KEMPublicKey: i.KEMPublicKey,
		DSAPublicKey: i.DSAPublicKey,
	}

	// Set up public key objects
	if len(i.KEMPublicKey) == MLKEMPublicKeySize {
		pub.kemPublicKeyObj, _ = mlkem.PublicKeyFromBytes(i.KEMPublicKey, mlkem.MLKEM768)
	}
	if len(i.DSAPublicKey) == MLDSAPublicKeySize {
		pub.dsaPublicKeyObj, _ = mldsa.PublicKeyFromBytes(i.DSAPublicKey, mldsa.MLDSA65)
	}

	return pub
}

// GenerateIdentity creates a new post-quantum identity using ML-KEM-768 and ML-DSA-65
func GenerateIdentity() (*Identity, error) {
	// Generate ML-KEM-768 keypair for key encapsulation
	kemPub, kemPriv, err := mlkem.GenerateKey(mlkem.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM keypair: %w", err)
	}

	// Generate ML-DSA-65 keypair for digital signatures
	dsaPriv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DSA keypair: %w", err)
	}

	kemPubBytes := kemPub.Bytes()
	kemSecBytes := kemPriv.Bytes()
	dsaPubBytes := dsaPriv.PublicKey.Bytes()
	dsaSecBytes := dsaPriv.Bytes()

	// Generate Session ID: "07" + Blake2b-256(KEM_pk || DSA_pk)
	h, _ := blake2b.New256(nil)
	h.Write(kemPubBytes)
	h.Write(dsaPubBytes)
	sessionID := PQPrefix + hex.EncodeToString(h.Sum(nil))

	return &Identity{
		SessionID:        sessionID,
		KEMPublicKey:     kemPubBytes,
		KEMSecretKey:     kemSecBytes,
		DSAPublicKey:     dsaPubBytes,
		DSASecretKey:     dsaSecBytes,
		kemPublicKeyObj:  kemPub,
		kemPrivateKeyObj: kemPriv,
		dsaPublicKeyObj:  dsaPriv.PublicKey,
		dsaPrivateKeyObj: dsaPriv,
	}, nil
}

// DeriveSessionID derives a session ID from public keys
func DeriveSessionID(kemPublicKey, dsaPublicKey []byte) (string, error) {
	if len(kemPublicKey) != MLKEMPublicKeySize {
		return "", ErrInvalidPublicKey
	}
	if len(dsaPublicKey) != MLDSAPublicKeySize {
		return "", ErrInvalidPublicKey
	}

	h, _ := blake2b.New256(nil)
	h.Write(kemPublicKey)
	h.Write(dsaPublicKey)
	return PQPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// Encapsulate performs ML-KEM-768 key encapsulation
// Returns: ciphertext, shared secret
func Encapsulate(recipientPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(recipientPublicKey) != MLKEMPublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}

	pubKey, err := mlkem.PublicKeyFromBytes(recipientPublicKey, mlkem.MLKEM768)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ciphertext, sharedSecret, err = pubKey.Encapsulate()
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return ciphertext, sharedSecret, nil
}

// Decapsulate performs ML-KEM-768 key decapsulation
func Decapsulate(secretKey, ciphertext []byte) (sharedSecret []byte, err error) {
	if len(secretKey) != MLKEMSecretKeySize {
		return nil, ErrInvalidSecretKey
	}
	if len(ciphertext) != MLKEMCiphertextSize {
		return nil, ErrInvalidCiphertext
	}

	privKey, err := mlkem.PrivateKeyFromBytes(secretKey, mlkem.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret key: %w", err)
	}

	sharedSecret, err = privKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	return sharedSecret, nil
}

// Sign creates an ML-DSA-65 signature
func Sign(secretKey, message []byte) (signature []byte, err error) {
	if len(secretKey) != MLDSASecretKeySize {
		return nil, ErrInvalidSecretKey
	}

	privKey, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret key: %w", err)
	}

	signature, err = privKey.Sign(rand.Reader, message, nil)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// Verify verifies an ML-DSA-65 signature
func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != MLDSAPublicKeySize {
		return false
	}
	if len(signature) != MLDSASignatureSize {
		return false
	}

	pubKey, err := mldsa.PublicKeyFromBytes(publicKey, mldsa.MLDSA65)
	if err != nil {
		return false
	}

	return pubKey.VerifySignature(message, signature)
}

// Encrypt encrypts a message using XChaCha20-Poly1305
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a message using XChaCha20-Poly1305
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, ErrInvalidCiphertext
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptToRecipient encrypts a message for a recipient using their public key
func EncryptToRecipient(recipientPublicKey, plaintext []byte) ([]byte, error) {
	// 1. Encapsulate to get ciphertext and shared secret
	kemCiphertext, sharedSecret, err := Encapsulate(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	// 2. Encrypt plaintext with shared secret
	encrypted, err := Encrypt(sharedSecret, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 3. Prepend KEM ciphertext
	result := make([]byte, len(kemCiphertext)+len(encrypted))
	copy(result, kemCiphertext)
	copy(result[len(kemCiphertext):], encrypted)

	return result, nil
}

// DecryptFromSender decrypts a message using our secret key
func DecryptFromSender(secretKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < MLKEMCiphertextSize {
		return nil, ErrInvalidCiphertext
	}

	// 1. Extract KEM ciphertext
	kemCiphertext := ciphertext[:MLKEMCiphertextSize]
	encrypted := ciphertext[MLKEMCiphertextSize:]

	// 2. Decapsulate to get shared secret
	sharedSecret, err := Decapsulate(secretKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	// 3. Decrypt with shared secret
	plaintext, err := Decrypt(sharedSecret, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// SignMessage signs a message and returns signature with message prepended
func (i *Identity) SignMessage(message []byte) ([]byte, error) {
	if i.dsaPrivateKeyObj == nil && len(i.DSASecretKey) > 0 {
		var err error
		i.dsaPrivateKeyObj, err = mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, i.DSASecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DSA secret key: %w", err)
		}
	}

	if i.dsaPrivateKeyObj == nil {
		return nil, ErrInvalidSecretKey
	}

	sig, err := i.dsaPrivateKeyObj.Sign(rand.Reader, message, nil)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Return signature || message
	result := make([]byte, len(sig)+len(message))
	copy(result, sig)
	copy(result[len(sig):], message)

	return result, nil
}

// VerifyMessage verifies a signed message (signature || message format)
func (i *Identity) VerifyMessage(signedMessage []byte) ([]byte, bool) {
	if len(signedMessage) < MLDSASignatureSize {
		return nil, false
	}

	signature := signedMessage[:MLDSASignatureSize]
	message := signedMessage[MLDSASignatureSize:]

	if i.dsaPublicKeyObj == nil && len(i.DSAPublicKey) > 0 {
		var err error
		i.dsaPublicKeyObj, err = mldsa.PublicKeyFromBytes(i.DSAPublicKey, mldsa.MLDSA65)
		if err != nil {
			return nil, false
		}
	}

	if i.dsaPublicKeyObj == nil {
		return nil, false
	}

	if !i.dsaPublicKeyObj.VerifySignature(message, signature) {
		return nil, false
	}

	return message, true
}

// EncryptTo encrypts a message for another identity
func (i *Identity) EncryptTo(recipient *Identity, plaintext []byte) ([]byte, error) {
	return EncryptToRecipient(recipient.KEMPublicKey, plaintext)
}

// DecryptFrom decrypts a message from a sender
func (i *Identity) DecryptFrom(ciphertext []byte) ([]byte, error) {
	return DecryptFromSender(i.KEMSecretKey, ciphertext)
}
