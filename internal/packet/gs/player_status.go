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
)

type PlayerLifecycleController struct {
	sessions  *service.SessionRegistry
	serverSvc *service.ServerList
}

const MaxPlayerSyncBatch = 256

var (
	ErrExceededBatchLimit = errors.New("player sync batch size exceeds maximum allowed limit")
)

// NewPlayerLifecycleController initializes the controller during server boot-up.
func NewPlayerLifecycleController(
	sessions *service.SessionRegistry,
	serverSvc *service.ServerList,
) *PlayerLifecycleController {
	return &PlayerLifecycleController{
		sessions:  sessions,
		serverSvc: serverSvc,
	}
}

// HandlePlayerInGame handles the notification from the game server that players have entered the game.
func (ctrl *PlayerLifecycleController) HandlePlayerInGame(
	gsc *client.GameServerClient,
	r *network.PacketReader,
) error {
	size, err := r.ReadInt16()
	if err != nil {
		return err
	}

	if size < 0 || size > MaxPlayerSyncBatch {
		return ErrExceededBatchLimit
	}

	for i := 0; i < int(size); i++ {
		account, fErr := r.ReadString()
		if fErr != nil {
			return fErr
		}

		ctrl.sessions.SetGS(account, gsc.ServerID)
		ctrl.serverSvc.AddPlayer(gsc.ServerID)
	}
	return nil
}

// HandlePlayerLogout handles the notification from the game server that a player has logged out.
func (ctrl *PlayerLifecycleController) HandlePlayerLogout(
	gsc *client.GameServerClient,
	r *network.PacketReader,
) error {
	account, err := r.ReadString()
	if err != nil {
		return err
	}

	sess, ok := ctrl.sessions.Get(account)
	if !ok || sess.ServerID != gsc.ServerID {
		return nil
	}

	if ctrl.sessions.Unregister(account, sess.SessionID) {
		ctrl.serverSvc.RemovePlayer(gsc.ServerID)
	}

	return nil
}
