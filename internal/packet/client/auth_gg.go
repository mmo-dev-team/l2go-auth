// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"github.com/mmo-dev-team/l2go-auth/internal/client"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/rs/zerolog/log"
)

// AuthGG handles the GameGuard authentication request from the client.
func AuthGG(c *client.Client, r *network.PacketReader) error {
	sessionID, err := r.ReadInt32()
	if err != nil {
		return err
	}

	if sessionID != c.SessionID {
		log.Warn().
			Str("ip", c.RemoteIP).
			Int32("expected", c.SessionID).
			Int32("received", sessionID).
			Msg("Invalid session ID")

		c.SendAndClose(ServerLoginFail, func(w *network.PacketWriter) {
			w.WriteByte(0x01) // REASON_SYSTEM_ERROR
		})
		return nil
	}

	c.State = client.StateAuthedGG

	c.Send(ServerAuthGG, func(w *network.PacketWriter) {
		w.WriteInt32(c.SessionID)
	})

	return nil
}
