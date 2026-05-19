// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"errors"

	"github.com/mmo-dev-team/l2go-auth/internal/client"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

const (
	// Client-side opcodes
	ClientLogin           = 0x00
	ClientGameServerLogin = 0x02
	ClientServerList      = 0x05
	ClientAuthGG          = 0x07

	// Server-side opcodes
	ServerInit        = 0x00
	ServerLoginFail   = 0x01
	ServerLoginBanned = 0x02
	ServerLoginOK     = 0x03
	ServerServerList  = 0x04
	ServerPlayOK      = 0x07
	ServerAuthGG      = 0x0B
)

var (
	ErrUnknownOpcode = errors.New("received unhandled or invalid network protocol opcode")
)

// Handler is a function type that handles a client packet.
type Handler func(c *client.Client, r *network.PacketReader) error

// Registry stores and routes packet handlers using a flat, cache-aligned array.
type Registry struct {
	handlers [256]Handler
}

// NewRegistry creates a new packet handler registry pre-allocated on the stack or heap layout.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register binds a specific handler function to an opcode slot.
func (reg *Registry) Register(opcode byte, handler Handler) {
	reg.handlers[opcode] = handler
}

// Handle routes the incoming byte buffer payload directly to its pre-compiled execution slice.
func (reg *Registry) Handle(c *client.Client, opcode byte, r *network.PacketReader) error {
	handler := reg.handlers[opcode]
	if handler == nil {
		return ErrUnknownOpcode
	}

	return handler(c, r)
}
