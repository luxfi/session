# Architecture

## System Overview

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
└─────────────────────────────────────────────────────────┘
```

## Components

### SessionVM (`vm/`)

Core virtual machine managing:
- Session lifecycle (pending → active → expired/closed)
- Message routing and storage
- Channel management
- JSON-RPC service

### Crypto (`crypto/`)

Post-quantum cryptographic operations:
- Identity generation
- Key encapsulation/decapsulation
- Digital signatures
- Authenticated encryption

## Session Lifecycle

```
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ PENDING  │────▶│  ACTIVE  │────▶│ EXPIRED  │
  └──────────┘     └────┬─────┘     └──────────┘
                        │
                        ▼
                  ┌──────────┐
                  │  CLOSED  │
                  └──────────┘
```

## Message Flow

1. **Create Session**: Participants exchange public keys
2. **Encapsulate**: Sender creates encrypted key for recipient
3. **Encrypt**: Message encrypted with derived shared key
4. **Sign**: Message signed with sender's ML-DSA key
5. **Transmit**: Ciphertext and signature sent
6. **Verify**: Recipient verifies signature
7. **Decrypt**: Recipient decapsulates and decrypts

## C++ Backend

For high-performance deployments: [luxcpp/session](https://github.com/luxcpp/session)

- GPU acceleration (Metal, CUDA, WebGPU)
- CGO bindings for Go integration
- Swarm-based distributed storage
