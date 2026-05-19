// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package gs

import (
	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

type AccountCharsController struct {
	ServerSvc *service.ServerList
}

// NewAccountCharsController creates a reusable controller instance during boot-up initialization.
func NewAccountCharsController(serverSvc *service.ServerList) *AccountCharsController {
	return &AccountCharsController{
		ServerSvc: serverSvc,
	}
}

// HandleReplyCharacters processes the character count dashboard reports directly from connected game servers.
func (ctrl *AccountCharsController) HandleReplyCharacters(
	gsc *client.GameServerClient,
	r *network.PacketReader,
) error {
	account, err := r.ReadString()
	if err != nil {
		return err
	}

	chars, err := r.ReadByte()
	if err != nil {
		return err
	}

	_, err = r.ReadByte()
	if err != nil {
		return err
	}

	ctrl.ServerSvc.SetCharCount(account, gsc.ServerID, chars)
	return nil
}
