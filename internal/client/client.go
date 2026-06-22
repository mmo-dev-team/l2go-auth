// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	loginCrypto "github.com/mmo-dev-team/l2go-auth/internal/crypto"

	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/panjf2000/gnet/v2"
	"github.com/rs/zerolog/log"
)

// State represents the current authentication state of a client.
type State byte

const (
	StateConnected State = iota
	StateAuthedGG
	StateAuthedLogin
	StateServerList
)

// Client represents a connected user on the Login Server.
type Client struct {
	Conn         gnet.Conn
	Crypt        *loginCrypto.Crypt
	ScrambledKey *crypto.ScrambledKey
	RemoteAddr   netip.Addr
	RemoteIP     string
	Account      string
	lastActivity atomic.Int64
	AccountID    int64
	SessionKey   crypto.SessionKey
	idMu         sync.RWMutex
	LastServer   int32
	SessionID    int32
	State        State
}

// Touch records the current time as the last activity timestamp (atomic, lock-free).
func (c *Client) Touch() {
	c.lastActivity.Store(time.Now().UnixNano())
}

// LastActivityNanos returns the last activity timestamp as Unix nanoseconds.
func (c *Client) LastActivityNanos() int64 {
	return c.lastActivity.Load()
}

// SetAccount publishes the authenticated account name under the identity.
func (c *Client) SetAccount(account string) {
	c.idMu.Lock()
	c.Account = account
	c.idMu.Unlock()
}

// AccountName reads the account name under the identity lock.
func (c *Client) AccountName() string {
	c.idMu.RLock()
	a := c.Account
	c.idMu.RUnlock()
	return a
}

// SendAsync sends a packet to the client asynchronously.
func (c *Client) SendAsync(opcode byte, build func(w *network.PacketWriter)) error {
	w := network.GetPacketWriter()
	defer network.PutPacketWriter(w)

	w.WriteByte(opcode)

	build(w)

	c.Crypt.Encrypt(w)

	w.PrependLength()

	out := append([]byte(nil), w.Bytes()...)
	return c.Conn.AsyncWrite(out, nil)
}

// SendAndCloseAsync sends a packet asynchronously and closes the connection.
func (c *Client) SendAndCloseAsync(opcode byte, build func(w *network.PacketWriter)) error {
	w := network.GetPacketWriter()
	defer network.PutPacketWriter(w)

	w.WriteByte(opcode)

	build(w)

	c.Crypt.Encrypt(w)

	w.PrependLength()

	out := append([]byte(nil), w.Bytes()...)
	return c.Conn.AsyncWrite(out, func(con gnet.Conn, _ error) error {
		return con.Close()
	})
}

// Close gracefully terminates the client connection.
func (c *Client) Close() error {
	log.Debug().Str("ip", c.RemoteIP).Msg("Closing connection")
	return c.Conn.Close()
}
