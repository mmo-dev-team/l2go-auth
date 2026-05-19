// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"errors"
	"net/netip"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/rs/zerolog/log"
)

type ServerDashboardController struct {
	ServerSvc *service.ServerList
	Kicker    service.Kicker
}

var (
	ErrUnauthorizedState = errors.New("client attempted to read server list prior to successful authentication login state")
)

// NewServerDashboardController provisions a reusable controller instance during boot initialization.
func NewDashboardController(serverSvc *service.ServerList, kicker service.Kicker) *ServerDashboardController {
	return &ServerDashboardController{
		ServerSvc: serverSvc,
		Kicker:    kicker,
	}
}

// HandleServerList marshals the active game server metrics and account dashboard fields.
func (ctrl *ServerDashboardController) HandleServerList(c *client.Client, r *network.PacketReader) error {
	if c.State != client.StateAuthedLogin {
		log.Warn().Str("ip", c.RemoteIP).Msg("ServerList requested before validation completed")
		return ErrUnauthorizedState
	}

	loginOK1, err := r.ReadInt32()
	if err != nil {
		return err
	}
	loginOK2, err := r.ReadInt32()
	if err != nil {
		return err
	}

	if !c.SessionKey.CheckLoginPair(loginOK1, loginOK2) {
		log.Warn().Str("ip", c.RemoteIP).Msg("Invalid session token sequence matched during list inquiry")
		_ = c.Close()
		return service.ErrInvalidPassword
	}

	c.State = client.StateServerList

	snap := ctrl.ServerSvc.GetServers()
	charCounts, hasChars := ctrl.ServerSvc.GetCharCounts(c.Account)

	if !hasChars {
		ctrl.Kicker.RequestCharacters(c.Account, c.AccountID)
	}

	c.Send(ServerServerList, func(w *network.PacketWriter) {
		w.WriteByte(byte(snap.Count))
		w.WriteByte(byte(c.LastServer))

		for i := 0; i < snap.Count; i++ {
			srv := &snap.Servers[i]
			w.WriteByte(byte(srv.ID))

			ipAddr, pErr := netip.ParseAddr(srv.IP)
			if pErr == nil && ipAddr.Is4() {
				octets := ipAddr.As4()
				w.WriteByte(octets[0])
				w.WriteByte(octets[1])
				w.WriteByte(octets[2])
				w.WriteByte(octets[3])
			} else {
				w.WriteByte(127)
				w.WriteByte(0)
				w.WriteByte(0)
				w.WriteByte(1)
			}

			w.WriteInt32(srv.Port)
			w.WriteByte(0x00) // Age Limit

			if srv.Pvp {
				w.WriteByte(0x01)
			} else {
				w.WriteByte(0x00)
			}

			w.WriteInt16(srv.CurrentPlayers)
			w.WriteInt16(srv.MaxPlayers)

			status := srv.Status
			if srv.CurrentPlayers >= srv.MaxPlayers {
				status = 0
			}
			w.WriteByte(status)
			w.WriteInt32(srv.ServerType)

			if srv.Brackets {
				w.WriteByte(0x01)
			} else {
				w.WriteByte(0x00)
			}
		}

		w.WriteInt16(0x00) // End of active server array layout marker
		w.WriteInt16(0xA4) // Character information packet segment header

		for i := 0; i < snap.Count; i++ {
			srvID := snap.Servers[i].ID
			w.WriteByte(byte(srvID))

			if hasChars && srvID >= 0 && srvID < service.MaxSupportedServers {
				w.WriteByte(charCounts[srvID])
			} else {
				w.WriteByte(0x00)
			}
		}
	})

	return nil
}
