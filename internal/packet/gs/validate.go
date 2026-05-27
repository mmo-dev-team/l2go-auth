// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package gs

import (
	"strings"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/session"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/rs/zerolog/log"
)

// HandleValidate executes the player validation sequence from the game server bridge.
func HandleValidate(gsc *client.GameServerClient, r *network.PacketReader) error {
	account, err := r.ReadString()
	if err != nil {
		return err
	}

	PlayOkID1, err := r.ReadInt32()
	if err != nil {
		return err
	}
	PlayOkID2, err := r.ReadInt32()
	if err != nil {
		return err
	}
	LoginOkID1, err := r.ReadInt32()
	if err != nil {
		return err
	}
	LoginOkID2, err := r.ReadInt32()
	if err != nil {
		return err
	}

	sess, ok := session.ValidateAndDelete(LoginOkID1)
	success := ok &&
		strings.EqualFold(sess.Account, account) &&
		sess.Key.CheckPlayPair(LoginOkID1, LoginOkID2, PlayOkID1, PlayOkID2)

	statusByte := byte(0)
	if success {
		statusByte = 1
	}

	gsc.Send(PlayerAuthResponse, func(w *network.PacketWriter) {
		w.WriteString(account)
		w.WriteByte(statusByte)
		w.WriteInt32(LoginOkID1)
		if success {
			w.WriteInt64(sess.AccountID)
		} else {
			w.WriteInt64(0)
		}
	})

	if success {
		log.Debug().
			Str("ip", gsc.RemoteIP).
			Str("account", account).
			Msg("Validate success")
	} else {
		log.Warn().
			Str("ip", gsc.RemoteIP).
			Str("account", account).
			Msg("Validate failed - invalid or expired security handshake keys")
	}

	return nil
}
