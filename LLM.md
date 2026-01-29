# SessionVM - Post-Quantum Secure Messaging

## Overview

SessionVM is a pluggable virtual machine for the Lux blockchain ecosystem that provides post-quantum secure private messaging. It can be integrated into any Lux-based chain to enable end-to-end encrypted communication.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│              (Pars, Messaging Apps, DAOs)               │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                github.com/luxfi/session                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   vm/vm.go  │  │ vm/service  │  │ crypto/identity │  │
│  │   SessionVM │  │    RPC      │  │  PQ Crypto Ops  │  │
│  └─────────────┘  └─────────────┘  └────────┬────────┘  │
└─────────────────────────────────────────────┼───────────┘
                                              │
┌─────────────────────────────────────────────▼───────────┐
│                github.com/luxfi/crypto                   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │   mlkem/   │  │   mldsa/   │  │   blake2b/       │   │
│  │ ML-KEM-768 │  │ ML-DSA-65  │  │   XChaCha20      │   │
│  └────────────┘  └────────────┘  └──────────────────┘   │
│        (cloudflare/circl FIPS implementations)          │
└─────────────────────────────────────────────────────────┘
```

## Key Components

### vm/vm.go - SessionVM Core
- Manages sessions, messages, and channels
- In-memory storage (extensible to persistent storage)
- Session lifecycle: pending → active → expired/closed

### vm/service.go - RPC Service
- JSON-RPC 2.0 over HTTP
- Methods: CreateSession, GetSession, SendMessage, CloseSession, Health

### vm/factory.go - VM Factory
- Creates SessionVM instances
- VMID: `sessionvm` (Base58: 2ZbQaVuXHtT7vfJt8FmWEQKAT4NgtPqWEZHg5m3tUvEiSMnQNt)

### crypto/identity.go - PQ Identity Management
- Uses `github.com/luxfi/crypto` for all cryptographic operations
- ML-KEM-768 for key encapsulation (NIST FIPS 203)
- ML-DSA-65 for digital signatures (NIST FIPS 204)
- XChaCha20-Poly1305 for symmetric encryption
- Session ID format: `07` + hex(Blake2b-256(KEM_pk || DSA_pk))

## Cryptographic Primitives

| Algorithm | Purpose | Standard | Key Sizes |
|-----------|---------|----------|-----------|
| ML-KEM-768 | Key encapsulation | FIPS 203 | PK: 1184, SK: 2400, CT: 1088 |
| ML-DSA-65 | Digital signatures | FIPS 204 | PK: 1952, SK: 4032, Sig: 3309 |
| XChaCha20-Poly1305 | AEAD encryption | RFC 8439 | Key: 32, Nonce: 24 |
| Blake2b-256 | Hashing | RFC 7693 | Output: 32 |

## Session ID Prefixes

- `07` - Post-quantum (ML-KEM + ML-DSA)
- `05` - Legacy (X25519 + Ed25519)

## Usage Example

```go
import (
    "github.com/luxfi/session/crypto"
    "github.com/luxfi/session/vm"
)

// Generate PQ identity
identity, err := crypto.GenerateIdentity()
// identity.SessionID: "07abc123..." (66 chars)
// identity.KEMPublicKey: 1184 bytes
// identity.DSAPublicKey: 1952 bytes

// Encrypt to recipient
ciphertext, err := crypto.EncryptToRecipient(recipientKEMPublicKey, plaintext)

// Sign message
signature, err := crypto.Sign(identity.DSASecretKey, message)

// Verify signature
valid := crypto.Verify(identity.DSAPublicKey, message, signature)
```

## Integration with Pars

Pars (github.com/parsdao/node) integrates SessionVM through `vm/session.go`:

```go
import "github.com/luxfi/session/vm"

provider, _ := vm.NewSessionProvider(logger)
identity, _ := provider.GenerateIdentity()
session, _ := provider.CreateSecureSession(ctx, identity, remotePublicKey)
```

## C++ Backend (Optional)

For high-performance deployments, a C++ storage server is available at `~/work/luxcpp/session/`:

- Full C++ implementation with GPU acceleration (Metal)
- CGO bindings for Go integration
- Compatible with Session network protocol

Build with:
```bash
cd ~/work/luxcpp/session
cmake -B build -DBUILD_CGO_LIB=ON
cmake --build build
```

## Dependencies

- `github.com/luxfi/crypto` - Cryptographic primitives (required)
- `github.com/luxfi/ids` - ID types
- `github.com/luxfi/log` - Logging
- `github.com/gorilla/rpc` - JSON-RPC server
- `github.com/cloudflare/circl` - PQ crypto (via luxfi/crypto)

## Configuration

```json
{
  "sessionTTL": 86400,      // Session timeout in seconds (24h default)
  "maxMessages": 10000,     // Max messages per session
  "maxChannels": 1000,      // Max channels
  "retentionDays": 30,      // Message retention
  "idPrefix": "07"          // Session ID prefix (07 = PQ)
}
```

## Security Considerations

1. **Post-Quantum Security**: ML-KEM-768 and ML-DSA-65 provide NIST Level 3 security
2. **Forward Secrecy**: Each message uses fresh KEM encapsulation
3. **Authentication**: All messages are signed with ML-DSA-65
4. **Confidentiality**: XChaCha20-Poly1305 provides authenticated encryption

## Status

- [x] Core VM implementation
- [x] PQ crypto integration with lux/crypto
- [x] RPC service
- [x] Pars integration
- [ ] Persistent storage backend
- [ ] Onion routing
- [ ] Group messaging
- [ ] Message delivery confirmation
