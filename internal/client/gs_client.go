// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"time"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/panjf2000/gnet/v2"
	"github.com/rs/zerolog/log"
)

// GameServerClient represents a connected Game Server on the internal listener.
type GameServerClient struct {
	LastActivity time.Time
	Conn         gnet.Conn
	RemoteIP     string
	ServerID     int32
}

// Send constructs a packet with the given opcode and body and sends it to the Game Server.
func (gsc *GameServerClient) Send(opcode byte, build func(w *network.PacketWriter)) error {
	w := network.GetPacketWriter()
	defer network.PutPacketWriter(w)

	w.WriteByte(opcode)

	build(w)

	w.PrependLength()

	if _, err := gsc.Conn.Write(w.Bytes()); err != nil {
		return err
	}

	gsc.LastActivity = time.Now()
	return nil
}

// SendAndClose sends a packet and then immediately closes the Game Server connection.
func (gsc *GameServerClient) SendAndClose(opcode byte, build func(w *network.PacketWriter)) error {
	gsc.Send(opcode, build)
	return gsc.Conn.Close()
}

// Close gracefully terminates the Game Server connection.
func (gsc *GameServerClient) Close() error {
	log.Debug().Str("ip", gsc.RemoteIP).Msg("Closing connection")
	return gsc.Conn.Close()
}
