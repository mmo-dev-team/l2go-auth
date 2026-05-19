// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package gs

import (
	"github.com/mmo-dev-team/l2go-auth/internal/client"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

const (
	// GS -> LS opcodes
	GameServerAuth    = 0x01
	PlayerInGame      = 0x02
	PlayerLogout      = 0x03
	PlayerAuthRequest = 0x05
	ReplyCharacters   = 0x08

	// LS -> GS opcodes
	InitLS             = 0x00
	AuthResponse       = 0x02
	PlayerAuthResponse = 0x03
	KickPlayer         = 0x04
	RequestCharacters  = 0x05
)

// Handler is a function type that handles a game server packet.
type Handler func(gsc *client.GameServerClient, r *network.PacketReader) error

// Registry stores and routes game server packet handlers based on opcodes.
type Registry struct {
	handlers [256]Handler
}

// NewRegistry creates a new game server packet handler registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a handler for a specific opcode.
func (reg *Registry) Register(opcode byte, handler Handler) {
	reg.handlers[opcode] = handler
}

// Handle routes the packet to the appropriate handler based on the opcode.
func (reg *Registry) Handle(gsc *client.GameServerClient, opcode byte, r *network.PacketReader) error {
	handler := reg.handlers[opcode]
	if handler == nil {
		// No handler assigned for this specific byte; discard or ignore the packet silently
		return nil
	}

	return handler(gsc, r)
}
