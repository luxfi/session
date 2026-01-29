# Cryptography

Post-quantum cryptographic primitives used in SessionVM.

## Algorithms

| Algorithm | Purpose | Standard | Security Level |
|-----------|---------|----------|----------------|
| ML-KEM-768 | Key Encapsulation | FIPS 203 | NIST Level 3 |
| ML-DSA-65 | Digital Signatures | FIPS 204 | NIST Level 3 |
| XChaCha20-Poly1305 | AEAD Encryption | RFC 8439 | 256-bit |
| Blake2b-256 | Hashing | RFC 7693 | 256-bit |

## Key Sizes

```
ML-KEM-768:
  Public Key:   1184 bytes
  Secret Key:   2400 bytes
  Ciphertext:   1088 bytes
  Shared Key:   32 bytes

ML-DSA-65:
  Public Key:   1952 bytes
  Secret Key:   4032 bytes
  Signature:    3309 bytes
```

## Session ID Format

Session IDs use a prefix to identify the cryptographic suite:

- `07` - Post-quantum (ML-KEM-768 + ML-DSA-65)
- `05` - Legacy (X25519 + Ed25519)

Format: `<prefix>` + hex(Blake2b-256(KEM_pk || DSA_pk)) = 66 characters

## Usage

### Identity Generation

```go
identity, err := crypto.GenerateIdentity()
// identity.SessionID: "07abc123..." (66 chars)
// identity.KEMPublicKey: 1184 bytes
// identity.DSAPublicKey: 1952 bytes
```

### Key Encapsulation

```go
// Sender encapsulates
ciphertext, sharedSecret, err := crypto.Encapsulate(recipientPublicKey)

// Recipient decapsulates
sharedSecret, err := crypto.Decapsulate(recipientSecretKey, ciphertext)
```

### Digital Signatures

```go
// Sign
signature, err := crypto.Sign(secretKey, message)

// Verify
valid := crypto.Verify(publicKey, message, signature)
```

### Authenticated Encryption

```go
// Encrypt
ciphertext, err := crypto.Encrypt(sharedKey, plaintext)

// Decrypt
plaintext, err := crypto.Decrypt(sharedKey, ciphertext)
```
