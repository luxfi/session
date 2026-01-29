# SessionVM

Post-quantum secure messaging VM for the Lux blockchain ecosystem.

[![CI](https://github.com/luxfi/session/actions/workflows/ci.yml/badge.svg)](https://github.com/luxfi/session/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/luxfi/session.svg)](https://pkg.go.dev/github.com/luxfi/session)

## Overview

SessionVM is a pluggable virtual machine that provides end-to-end encrypted, post-quantum secure private messaging. It can be integrated into any Lux-based chain to enable secure communication.

## Features

- **Post-Quantum Security**: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204)
- **Forward Secrecy**: Fresh KEM encapsulation per message
- **Authenticated Encryption**: XChaCha20-Poly1305 AEAD
- **Pluggable Architecture**: Integrate into any Lux SDK chain
- **High Performance**: Optimized for low-latency messaging

## Installation

```bash
go get github.com/luxfi/session
```

## Quick Start

```go
import (
    "github.com/luxfi/session/crypto"
    "github.com/luxfi/session/vm"
)

// Generate post-quantum identity
identity, err := crypto.GenerateIdentity()
// identity.SessionID: "07abc123..." (66 chars)
// identity.KEMPublicKey: 1184 bytes (ML-KEM-768)
// identity.DSAPublicKey: 1952 bytes (ML-DSA-65)

// Encrypt to recipient
ciphertext, err := crypto.EncryptToRecipient(recipientKEMPublicKey, plaintext)

// Sign message
signature, err := crypto.Sign(identity.DSASecretKey, message)

// Verify signature
valid := crypto.Verify(identity.DSAPublicKey, message, signature)
```

## Cryptographic Primitives

| Algorithm | Purpose | Standard | Security Level |
|-----------|---------|----------|----------------|
| ML-KEM-768 | Key Encapsulation | FIPS 203 | NIST Level 3 |
| ML-DSA-65 | Digital Signatures | FIPS 204 | NIST Level 3 |
| XChaCha20-Poly1305 | AEAD Encryption | RFC 8439 | 256-bit |
| Blake2b-256 | Hashing | RFC 7693 | 256-bit |

## Session ID Format

Session IDs use a prefix system to identify the cryptographic suite:

- `07` - Post-quantum (ML-KEM-768 + ML-DSA-65)
- `05` - Legacy (X25519 + Ed25519)

Format: `<prefix>` + hex(Blake2b-256(KEM_pk || DSA_pk)) = 66 characters

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

## Related Repositories

- **[luxcpp/session](https://github.com/luxcpp/session)** - C++ storage server with GPU acceleration
- **[luxfi/crypto](https://github.com/luxfi/crypto)** - Cryptographic primitives (ML-KEM, ML-DSA, Blake2b)
- **[parsdao/node](https://github.com/parsdao/node)** - Pars blockchain node with SessionVM integration

## Benchmarks

On Apple M1 Max:

```
BenchmarkGenerateIdentity:         268μs/op
BenchmarkEncapsulateDecapsulate:   226μs/op
BenchmarkSignVerify:               1.08ms/op
BenchmarkCreateSession:            3.8μs/op
BenchmarkSendMessage:              1.9μs/op
BenchmarkGetSession:               16ns/op
```

## Testing

```bash
# Run all tests with race detection
go test -v -race ./...

# Run benchmarks
go test -bench=. -benchmem ./...
```

## Configuration

```json
{
  "sessionTTL": 86400,
  "maxMessages": 10000,
  "maxChannels": 1000,
  "retentionDays": 30,
  "idPrefix": "07"
}
```

## Documentation

- [LLM.md](./LLM.md) - Detailed architecture documentation
- [API Reference](https://pkg.go.dev/github.com/luxfi/session)

## License

Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
See [LICENSE](./LICENSE) for details.
