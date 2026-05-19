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

type ServerStatusController struct {
	ServerSvc *service.ServerList
}

const MaxStatusAttributes = 16

var (
	ErrMalformedPacketSize = errors.New("packet update batch size exceeds maximum permitted threshold")
)

// NewServerStatusController builds a reusable controller instance during system initialization.
func NewServerStatusController(serverSvc *service.ServerList) *ServerStatusController {
	return &ServerStatusController{
		ServerSvc: serverSvc,
	}
}

// HandleStatus processes batch updates directly from connected game server links.
func (ctrl *ServerStatusController) HandleStatus(gsc *client.GameServerClient, r *network.PacketReader) error {
	size, err := r.ReadInt32()
	if err != nil {
		return err
	}

	if size < 0 || size > MaxStatusAttributes {
		return ErrMalformedPacketSize
	}

	for i := 0; i < int(size); i++ {
		infoType, fErr := r.ReadInt32()
		if fErr != nil {
			return fErr
		}

		value, fErr := r.ReadInt32()
		if fErr != nil {
			return fErr
		}

		ctrl.ServerSvc.UpdateStatus(gsc.ServerID, int(infoType), value)
	}

	return nil
}
