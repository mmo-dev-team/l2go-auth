// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package listener

import (
	"sync"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/packet/gs"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/panjf2000/gnet/v2"
	"github.com/rs/zerolog/log"
)

// GameServerListener handles network connections from game servers.
type GameServerListener struct {
	*gnet.BuiltinEventEngine
	Engine     *gnet.Engine
	serverList *service.ServerList
	sessions   *service.SessionRegistry
	registry   *gs.Registry
	servers    map[gnet.Conn]*client.GameServerClient
	stopCh     chan struct{}
	timeout    time.Duration
	serverMu   sync.Mutex
}

// NewGameServerListener creates a new instance of GameServerListener.
func NewGameServerListener(
	serverList *service.ServerList,
	sessions *service.SessionRegistry,
	timeout time.Duration,
) *GameServerListener {
	listener := &GameServerListener{
		serverList: serverList,
		sessions:   sessions,
		servers:    make(map[gnet.Conn]*client.GameServerClient),
		registry:   gs.NewRegistry(),
		stopCh:     make(chan struct{}),
		timeout:    timeout,
	}

	initCtrl := gs.NewServerInitController(serverList)
	playerCtrl := gs.NewPlayerLifecycleController(sessions, serverList)
	charCtrl := gs.NewAccountCharsController(serverList)
	statusCtrl := gs.NewServerStatusController(serverList)

	listener.registry.Register(gs.GameServerAuth, initCtrl.HandleInit)
	listener.registry.Register(gs.PlayerInGame, playerCtrl.HandlePlayerInGame)
	listener.registry.Register(gs.PlayerLogout, playerCtrl.HandlePlayerLogout)
	listener.registry.Register(gs.PlayerAuthRequest, gs.HandleValidate)
	listener.registry.Register(gs.ReplyCharacters, charCtrl.HandleReplyCharacters)
	listener.registry.Register(gs.ServerStatusUpdate, statusCtrl.HandleStatus)

	return listener
}

// OnBoot is called when the game server listener engine is ready.
func (gsl *GameServerListener) OnBoot(eng gnet.Engine) (action gnet.Action) {
	gsl.Engine = &eng
	return gnet.None
}

// OnOpen is called when a game server establishes a connection.
func (gsl *GameServerListener) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	ip := getIP(c)

	gsc := &client.GameServerClient{
		Conn:     c,
		RemoteIP: ip,
	}
	gsc.Touch()

	gsl.serverMu.Lock()
	gsl.servers[c] = gsc
	gsl.serverMu.Unlock()

	c.SetContext(gsc)

	log.Debug().Str("ip", ip).Msg("Game server connected")
	return nil, gnet.None
}

// OnTraffic is called when data is received from a game server.
func (gsl *GameServerListener) OnTraffic(c gnet.Conn) (action gnet.Action) {
	gsc := c.Context().(*client.GameServerClient)

	buf, err := c.Next(-1)
	if err != nil {
		return gnet.Close
	}

	for {
		if len(buf) < 2 { // Minimum size for length header
			break
		}

		size := int(uint16(buf[0]) | uint16(buf[1])<<8)

		if size < network.MinPacketSize || size > network.MaxPacketSize {
			log.Error().Int("size", size).Msg("Invalid packet size")
			return gnet.Close
		}

		if len(buf) < size {
			break
		}

		payload := buf[2:size]

		opcode := payload[0]
		reader, rErr := network.GetPacketReader(payload[1:])
		if rErr != nil {
			log.Error().Err(rErr).Msg("PacketReader failed")
			return gnet.Close
		}

		err = gsl.registry.Handle(gsc, opcode, reader)

		network.PutPacketReader(reader)

		if err != nil {
			log.Error().
				Err(err).
				Str("ip", gsc.RemoteIP).
				Uint8("opcode", opcode).
				Msg("Packet handler error")
			return gnet.Close
		}

		gsc.Touch()

		buf = buf[size:]
		c.Discard(size)
	}

	return gnet.None
}

// OnClose is called when a game server connection is closed.
func (gsl *GameServerListener) OnClose(c gnet.Conn, _ error) (action gnet.Action) {
	gsl.serverMu.Lock()
	gsc, ok := gsl.servers[c]
	if ok {
		delete(gsl.servers, c)
	}
	gsl.serverMu.Unlock()

	if ok && gsc.ServerID != 0 {
		gsl.serverList.Unregister(gsc.ServerID)
		gsl.sessions.ClearServer(gsc.ServerID)

		log.Debug().Str("ip", gsc.RemoteIP).
			Int("server_id", int(gsc.ServerID)).
			Msg("Game server disconnected")
	}

	return gnet.None
}

// OnShutdown is called when the game server listener is shutting down.
func (gsl *GameServerListener) OnShutdown(_ gnet.Engine) {
	close(gsl.stopCh)
}

// OnTick is called periodically to perform maintenance tasks.
func (gsl *GameServerListener) OnTick() (delay time.Duration, action gnet.Action) {
	nowNanos := time.Now().UnixNano()
	timeout := int64(gsl.timeout)

	gsl.serverMu.Lock()
	for conn, cl := range gsl.servers {
		if nowNanos-cl.LastActivityNanos() > timeout {
			log.Warn().Str("ip", cl.RemoteIP).Msg("Connection timeout")
			conn.Close()
			delete(gsl.servers, conn)
		}
	}
	gsl.serverMu.Unlock()

	return 5 * time.Second, gnet.None // Run cleanup every 5 seconds
}

// KickAccount sends a kick request to the specified game server for a given user.
func (gsl *GameServerListener) KickAccount(username string, serverID int32) {
	gsl.serverMu.Lock()
	defer gsl.serverMu.Unlock()

	for _, gsc := range gsl.servers {
		if gsc.ServerID == serverID {
			log.Debug().
				Str("account", username).
				Int32("server_id", serverID).
				Msg("Sending KickPlayer to Game Server")
			gsc.Send(gs.KickPlayer, func(w *network.PacketWriter) {
				w.WriteString(username)
			})
			break
		}
	}
}

// RequestCharacters requests the character list for a specific account from all connected game servers.
func (gsl *GameServerListener) RequestCharacters(username string, accountID int64) {
	gsl.serverMu.Lock()
	defer gsl.serverMu.Unlock()

	for _, gsc := range gsl.servers {
		log.Debug().
			Str("account", username).
			Int32("server_id", gsc.ServerID).
			Msg("Requesting characters from Game Server")
		gsc.Send(gs.RequestCharacters, func(w *network.PacketWriter) {
			w.WriteString(username)
			w.WriteInt64(accountID)
		})
	}
}
