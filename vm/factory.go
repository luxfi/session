// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// VMID is the unique identifier for SessionVM
// Base58: 2ZbQaVuXHtT7vfJt8FmWEQKAT4NgtPqWEZHg5m3tUvEiSMnQNt
var VMID = ids.ID{'s', 'e', 's', 's', 'i', 'o', 'n', 'v', 'm'}

// Name is the human-readable name for this VM
const Name = "sessionvm"

// Factory creates new SessionVM instances
type Factory struct{}

// New returns a new instance of the SessionVM
func (f *Factory) New(logger log.Logger) (*VM, error) {
	vm := &VM{
		sessions: make(map[ids.ID]*Session),
		messages: make(map[ids.ID]*Message),
		channels: make(map[ids.ID]*Channel),
		pending:  make([]*Message, 0),
	}
	if err := vm.Initialize(logger, nil); err != nil {
		return nil, err
	}
	return vm, nil
}
