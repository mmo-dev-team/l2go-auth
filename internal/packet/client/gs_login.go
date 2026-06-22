// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"context"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/service"
	"github.com/mmo-dev-team/l2go-auth/internal/session"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/rs/zerolog/log"
)

// GameServerLogin creates a handler for the game server login request.
func GameServerLogin(auth *service.Authenticator, handoffTTL time.Duration) Handler {
	return func(c *client.Client, r *network.PacketReader) error {
		if c.State != client.StateServerList {
			log.Warn().Str("ip", c.RemoteIP).Msg("GameServerLogin before server list")
			return nil
		}

		loginOK1, err := r.ReadInt32()
		if err != nil {
			return err
		}
		loginOK2, err := r.ReadInt32()
		if err != nil {
			return err
		}
		serverID, err := r.ReadInt32()
		if err != nil {
			return err
		}

		if serverID < 0 || serverID >= service.MaxSupportedServers {
			log.Warn().Str("ip", c.RemoteIP).Int32("server_id", serverID).Msg("Client requested invalid server ID")
			return c.Close()
		}

		if !c.SessionKey.CheckLoginPair(loginOK1, loginOK2) {
			log.Warn().Str("ip", c.RemoteIP).Msg("Invalid session key")
			return c.Close()
		}

		if c.LastServer != serverID {
			c.LastServer = serverID
			auth.UpdateLastServer(context.Background(), c.Account, serverID)
		}

		s := &session.Session{
			ExpiresAt: time.Now().Add(handoffTTL),
			Key:       &c.SessionKey,
			ServerID:  serverID,
			AccountID: c.AccountID,
			Account:   c.Account,
		}

		session.Put(c.SessionKey.LoginOkID1, s)

		return c.SendAsync(ServerPlayOK, func(w *network.PacketWriter) {
			w.WriteInt32(c.SessionKey.PlayOkID1)
			w.WriteInt32(c.SessionKey.PlayOkID2)
		})
	}
}
