// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package gs

import (
	"errors"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/rs/zerolog/log"
)

type ServerInitController struct {
	ServerSvc *service.ServerList
}

const (
	MaxHexKeySize    = 512
	MaxHostCountCeil = 8
)

var (
	ErrPayloadTooLarge = errors.New("handshake payload size exceeds allowed security threshold")
)

// NewServerInitController instantiates the controller during boot-up initialization.
func NewServerInitController(serverSvc *service.ServerList) *ServerInitController {
	return &ServerInitController{
		ServerSvc: serverSvc,
	}
}

// HandleInit processes the initial validation and environment setup for a connecting Game Server.
func (ctrl *ServerInitController) HandleInit(gsc *client.GameServerClient, r *network.PacketReader) error {
	serverID, err := r.ReadByte()
	if err != nil {
		return err
	}

	// Skips: 2 bytes
	if _, err = r.ReadByte(); err != nil {
		return err
	}
	if _, err = r.ReadByte(); err != nil {
		return err
	}

	serverPort, err := r.ReadInt16()
	if err != nil {
		return err
	}
	maxPlayers, err := r.ReadInt32()
	if err != nil {
		return err
	}

	hexSize, err := r.ReadInt32()
	if err != nil {
		return err
	}
	if hexSize < 0 || hexSize > MaxHexKeySize {
		return ErrPayloadTooLarge
	}

	if _, err = r.ReadBytes(int(hexSize)); err != nil {
		return err
	}

	hostCount, err := r.ReadInt32()
	if err != nil {
		return err
	}
	if hostCount < 0 || hostCount > MaxHostCountCeil {
		return ErrPayloadTooLarge
	}

	var serverHost string
	if hostCount > 0 {
		serverHost, err = r.ReadString()
		if err != nil {
			return err
		}
		for i := 1; i < int(hostCount); i++ {
			if err = r.SkipString(); err != nil {
				return err
			}
		}
	}

	pvp, err := r.ReadByte()
	if err != nil {
		return err
	}
	brackets, err := r.ReadByte()
	if err != nil {
		return err
	}
	serverType, err := r.ReadInt32()
	if err != nil {
		return err
	}

	sid := int32(serverID)
	gsc.ServerID = sid

	srvConfig := service.Server{
		ID:             sid,
		IP:             serverHost,
		Port:           int32(serverPort),
		CurrentPlayers: 0,
		MaxPlayers:     int16(maxPlayers),
		Pvp:            pvp == 1,
		Brackets:       brackets == 1,
		ServerType:     serverType,
		Status:         1,
	}

	ctrl.ServerSvc.Register(&srvConfig)

	log.Info().
		Int32("server_id", sid).
		Str("host", serverHost).
		Int16("port", serverPort).
		Msg("Game Server authenticated and registered")

	gsc.Send(AuthResponse, func(w *network.PacketWriter) {
		w.WriteByte(serverID)
	})

	return nil
}
