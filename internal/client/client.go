// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
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
	LastActivity time.Time
	Conn         gnet.Conn
	Crypt        *loginCrypto.Crypt
	ScrambledKey *crypto.ScrambledKey
	SessionKey   crypto.SessionKey
	RemoteIP     string
	Account      string
	AccountID    int64
	LastServer   int32
	SessionID    int32
	State        State
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
