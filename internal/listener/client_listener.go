// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package listener

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	loginCrypto "github.com/mmo-dev-team/l2go-auth/internal/crypto"
	"github.com/mmo-dev-team/l2go-auth/internal/db"
	"github.com/mmo-dev-team/l2go-auth/internal/metrics"
	"github.com/mmo-dev-team/l2go-auth/internal/middleware"
	clientPacket "github.com/mmo-dev-team/l2go-auth/internal/packet/client"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/panjf2000/gnet/v2"
	"github.com/rs/zerolog/log"
)

// ClientListener handles incoming network connections from game clients.
// It manages client sessions, authentication, and packet routing.
type ClientListener struct {
	clientMu sync.Mutex
	timeout  time.Duration
	*gnet.BuiltinEventEngine
	Engine     *gnet.Engine
	queries    *db.Queries
	serverList *service.ServerList
	auth       *service.Authenticator
	sessions   *service.SessionRegistry
	bans       *service.BanManager
	limiter    *middleware.RateLimiter
	kicker     service.Kicker
	registry   *clientPacket.Registry
	clients    map[gnet.Conn]*client.Client
	stopCh     chan struct{}
}

// NewClientListener creates a new instance of ClientListener.
func NewClientListener(
	queries *db.Queries,
	serverList *service.ServerList,
	auth *service.Authenticator,
	sessions *service.SessionRegistry,
	bans *service.BanManager,
	limiter *middleware.RateLimiter,
	kicker service.Kicker,
	timeout time.Duration,
) *ClientListener {
	listener := &ClientListener{
		queries:    queries,
		serverList: serverList,
		auth:       auth,
		sessions:   sessions,
		bans:       bans,
		limiter:    limiter,
		kicker:     kicker,
		timeout:    timeout,
		clients:    make(map[gnet.Conn]*client.Client),
		registry:   clientPacket.NewRegistry(),
		stopCh:     make(chan struct{}),
	}

	loginCtrl := clientPacket.NewLoginController(auth, sessions, bans, kicker)
	serverListCtrl := clientPacket.NewDashboardController(serverList, kicker)

	listener.registry.Register(clientPacket.ClientAuthGG, clientPacket.AuthGG)
	listener.registry.Register(clientPacket.ClientLogin, loginCtrl.HandleLogin)
	listener.registry.Register(clientPacket.ClientServerList, serverListCtrl.HandleServerList)
	listener.registry.Register(clientPacket.ClientGameServerLogin, clientPacket.GameServerLogin(auth))

	return listener
}

// OnBoot is called when the engine is ready to accept connections.
func (l *ClientListener) OnBoot(eng gnet.Engine) (action gnet.Action) {
	l.Engine = &eng
	return gnet.None
}

// OnOpen is called when a new connection is opened.
// It sends the initial server packet (Init) to the client.
func (l *ClientListener) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	ip := getIP(c)

	// 1. Check Rate Limit (Connection Flood Protection)
	if l.limiter.IsLimited(ip) {
		log.Warn().Str("ip", ip).Msg("Rate limit exceeded, dropping connection")
		return nil, gnet.Close
	}
	l.limiter.AddAttempt(ip)

	ipAddr, _ := netip.ParseAddr(ip)

	if l.bans.IsBanned(ipAddr) {
		log.Warn().Str("ip", ip).Msg("Banned IP attempt")
		return nil, gnet.Close
	}

	sessionID := generateSessionID()
	sessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, gnet.Close
	}
	scrambledKey, err := crypto.GetScrambledKey()
	if err != nil {
		return nil, gnet.Close
	}
	secretKey := crypto.GetRandomBlowFishKey(int(sessionID))
	crypt := loginCrypto.NewCrypt(secretKey)

	cl := &client.Client{
		Conn:         c,
		RemoteIP:     ip,
		Crypt:        crypt,
		ScrambledKey: scrambledKey,
		SessionKey:   *sessionKey,
		SessionID:    sessionID,
		State:        client.StateConnected,
		LastActivity: time.Now(),
	}

	l.clientMu.Lock()
	l.clients[c] = cl
	l.clientMu.Unlock()

	metrics.ActiveConnections.Inc()
	metrics.ConnectionTotal.Inc()

	c.SetContext(cl)

	w := network.GetPacketWriter()
	defer network.PutPacketWriter(w)

	w.WriteByte(clientPacket.ServerInit)
	w.WriteInt32(sessionID)
	w.WriteInt32(0x0000c621) // Protocol revision for Lineage II login server
	w.WriteBytes(scrambledKey.Modulus[:])
	// Static XOR keys used for packet validation in the client
	w.WriteUint32(0x29DD954E)
	w.WriteUint32(0x77C39CFC)
	w.WriteUint32(0x97ADB620)
	w.WriteUint32(0x07BDE0F7)
	w.WriteBytes(secretKey)
	w.WriteByte(0x00) // Null terminator for the key

	staticCrypt := loginCrypto.NewCrypt(loginCrypto.StaticKey)
	staticCrypt.Encrypt(w)

	w.PrependLength()

	log.Debug().Str("ip", ip).Int32("session", sessionID).Msg("Client connected")
	return w.Bytes(), gnet.None
}

// OnTraffic is called when there is data available to read from the connection.
func (l *ClientListener) OnTraffic(c gnet.Conn) (action gnet.Action) {
	cl := c.Context().(*client.Client)

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

		if !cl.Crypt.Decrypt(payload, len(payload)) {
			log.Error().Str("ip", cl.RemoteIP).Msg("Decryption failed")
			return gnet.Close
		}

		if len(payload) < 1 { // Minimum size for opcode
			return gnet.Close
		}

		opcode := payload[0]
		reader, rErr := network.GetPacketReader(payload[1:])
		if rErr != nil {
			log.Error().Err(rErr).Msg("PacketReader failed")
			return gnet.Close
		}

		err = l.registry.Handle(cl, opcode, reader)

		network.PutPacketReader(reader)

		if err != nil {
			log.Error().
				Err(err).
				Str("ip", cl.RemoteIP).
				Uint8("opcode", opcode).
				Msg("Packet handler error")
			return gnet.Close
		}

		cl.LastActivity = time.Now()

		buf = buf[size:]
		c.Discard(size)
	}

	return gnet.None
}

// OnClose is called when a connection is closed.
func (l *ClientListener) OnClose(c gnet.Conn, _ error) (action gnet.Action) {
	l.clientMu.Lock()
	cl, ok := l.clients[c]
	if ok {
		delete(l.clients, c)
		if cl.Account != "" {
			if sess, active := l.sessions.Get(cl.Account); active && sess.SessionID == cl.SessionID {
				if sess.ServerID == 0 {
					l.sessions.Unregister(cl.Account, cl.SessionID)
					l.serverList.RemoveAccount(cl.Account)
				}
			}
		}
	}
	l.clientMu.Unlock()

	if ok {
		metrics.ActiveConnections.Dec()
		log.Debug().Str("ip", cl.RemoteIP).Msg("Client disconnected")
	}

	return gnet.None
}

// OnShutdown is called when the engine is shutting down.
func (l *ClientListener) OnShutdown(_ gnet.Engine) {
	close(l.stopCh)
}

// OnTick is called periodically by the engine.
// It checks for timed-out client connections.
func (l *ClientListener) OnTick() (delay time.Duration, action gnet.Action) {
	now := time.Now()

	l.clientMu.Lock()
	for conn, cl := range l.clients {
		if now.Sub(cl.LastActivity) > l.timeout {
			log.Warn().Str("ip", cl.RemoteIP).Msg("Connection timeout")
			conn.Close()
			delete(l.clients, conn)
			metrics.ActiveConnections.Dec()
		}
	}
	l.clientMu.Unlock()

	return 5 * time.Second, gnet.None // Run cleanup every 5 seconds
}

// KickAccount disconnects any client currently logged in with the specified username.
func (l *ClientListener) KickAccount(username string) {
	l.clientMu.Lock()
	defer l.clientMu.Unlock()

	for conn, cl := range l.clients {
		if cl.Account == username {
			log.Info().Str("account", username).Msg("Kicking account from Login Server")
			conn.Close()
			delete(l.clients, conn)
			break
		}
	}
}

func getIP(c gnet.Conn) string {
	if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return c.RemoteAddr().String()
}

var globalSessionID atomic.Int32

func generateSessionID() int32 {
	return globalSessionID.Add(1) ^ int32(time.Now().UnixNano())
}
