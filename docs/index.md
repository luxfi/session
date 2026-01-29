# SessionVM Documentation

Post-quantum secure messaging VM for the Lux blockchain ecosystem.

## Quick Start

```go
import (
    "github.com/luxfi/session/crypto"
    "github.com/luxfi/session/vm"
)

// Generate post-quantum identity
identity, err := crypto.GenerateIdentity()

// Encrypt to recipient
ciphertext, err := crypto.EncryptToRecipient(recipientKEMPublicKey, plaintext)

// Sign message
signature, err := crypto.Sign(identity.DSASecretKey, message)
```

## Contents

- [Cryptography](./crypto.md) - Post-quantum cryptographic primitives
- [Architecture](./architecture.md) - System design and components
- [Integration](./integration.md) - Integrating SessionVM into your chain
- [API Reference](https://pkg.go.dev/github.com/luxfi/session) - Go package documentation

## Related

- [luxcpp/session](https://github.com/luxcpp/session) - C++ storage server
- [luxfi/crypto](https://github.com/luxfi/crypto) - Cryptographic primitives
- [parsdao/node](https://github.com/parsdao/node) - Pars blockchain integration
