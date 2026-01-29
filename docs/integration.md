# Integration Guide

## Installing SessionVM

```bash
go get github.com/luxfi/session
```

## Basic Integration

```go
import (
    "github.com/luxfi/session/crypto"
    sessionvm "github.com/luxfi/session/vm"
    "github.com/luxfi/log"
)

// Create VM
logger := log.NewWriter(os.Stdout)
factory := &sessionvm.Factory{}
vm, err := factory.New(logger)
if err != nil {
    log.Fatal(err)
}

// Create session
participants := []ids.ID{participant1, participant2}
publicKeys := [][]byte{pubKey1, pubKey2}
session, err := vm.CreateSession(participants, publicKeys)

// Send message
msg, err := vm.SendMessage(session.ID, senderID, ciphertext, signature)

// Close session
err = vm.CloseSession(session.ID)
```

## Pars Integration

```go
import (
    "github.com/luxfi/session/crypto"
    sessionvm "github.com/luxfi/session/vm"
)

type SessionProvider struct {
    vm     *sessionvm.VM
    logger log.Logger
}

func NewSessionProvider(logger log.Logger) (*SessionProvider, error) {
    factory := &sessionvm.Factory{}
    vm, err := factory.New(logger)
    if err != nil {
        return nil, err
    }
    return &SessionProvider{vm: vm, logger: logger}, nil
}

func (sp *SessionProvider) GenerateIdentity() (*crypto.Identity, error) {
    return crypto.GenerateIdentity()
}

func (sp *SessionProvider) CreateSecureSession(
    ctx context.Context,
    identity *crypto.Identity,
    remotePublicKey []byte,
) (*SecureSession, error) {
    // Implementation
}
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

## RPC Endpoints

SessionVM exposes JSON-RPC 2.0 endpoints:

- `session.create` - Create new session
- `session.get` - Get session by ID
- `session.close` - Close session
- `session.send` - Send message
- `session.health` - Health check
