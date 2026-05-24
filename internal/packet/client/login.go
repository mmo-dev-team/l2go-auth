// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/metrics"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
	"github.com/mmo-dev-team/l2go-auth/pkg/network"

	"github.com/rs/zerolog/log"
)

// LoginController manages the account authentication flow, including RSA decryption,
// password hashing verification, and session registration.
type LoginController struct {
	auth     *service.Authenticator
	sessions *service.SessionRegistry
	bans     *service.BanManager
	kicker   service.Kicker
	sem      chan struct{}
}

// NewLoginController provisions the auth engine layout during initialization.
func NewLoginController(
	auth *service.Authenticator,
	sessions *service.SessionRegistry,
	bans *service.BanManager,
	kicker service.Kicker,
) *LoginController {
	workers := runtime.NumCPU() * 2
	if workers < 8 {
		workers = 8
	}
	return &LoginController{
		auth:     auth,
		sessions: sessions,
		bans:     bans,
		kicker:   kicker,
		sem:      make(chan struct{}, workers),
	}
}

// HandleLogin processes client credentials safely and maps state configurations.
func (ctrl *LoginController) HandleLogin(c *client.Client, r *network.PacketReader) error {
	if c.State != client.StateAuthedGG {
		log.Warn().Str("ip", c.RemoteIP).Msg("Login request dropped: GameGuard verification incomplete")
		return sendLoginFail(c, 0x01) // REASON_SYSTEM_ERROR
	}

	block1, block2, err := readLoginBlocks(r)
	if err != nil {
		log.Error().Err(err).Str("ip", c.RemoteIP).Msg("Failed to read login blocks")
		return sendLoginFail(c, 0x01)
	}

	go ctrl.processLogin(c, block1, block2)
	return nil
}

// processLogin runs off the event loop. The login protocol is strictly
// request/response — the client cannot send its next packet until it receives
// our reply — so the connection-state mutations here are safely ordered before
// the next OnTraffic for this connection. All replies go out via AsyncWrite.
func (ctrl *LoginController) processLogin(c *client.Client, block1, block2 []byte) {
	ctrl.sem <- struct{}{}
	defer func() { <-ctrl.sem }()

	username, password, err := decodeCredentials(c.ScrambledKey, block1, block2)
	if err != nil {
		log.Error().Err(err).Str("ip", c.RemoteIP).Msg("Failed to decode cipher identity structures")
		_ = sendLoginFail(c, 0x01)
		return
	}

	account, err := ctrl.auth.Authenticate(context.Background(), username, password, c.RemoteIP)
	if err != nil {
		metrics.LoginAttempts.WithLabelValues("fail", getFailLabel(err)).Inc()
		log.Warn().Err(err).Str("ip", c.RemoteIP).Str("username", username).Msg("Authentication failed")
		ipAddr, nErr := netip.ParseAddr(c.RemoteIP)
		if nErr != nil {
			ipAddr = netip.IPv4Unspecified()
		}
		ctrl.bans.RecordFailure(ipAddr)

		if errors.Is(err, service.ErrAccountBanned) {
			_ = c.SendAndCloseAsync(ServerLoginBanned, func(w *network.PacketWriter) {
				w.WriteByte(0x20) // Banned payload reason code
			})
			return
		}
		_ = sendLoginFail(c, getFailReasonFromError(err))
		return
	}

	metrics.LoginAttempts.WithLabelValues("success", "").Inc()
	kickOld, allow := ctrl.sessions.TryRegister(username)
	if !allow {
		_ = sendLoginFail(c, 0x07) // REASON_ACCOUNT_IN_USE
		return
	}

	if kickOld {
		if sess, ok := ctrl.sessions.Get(username); ok {
			if sess.ServerID == 0 {
				ctrl.kicker.KickAccount(username)
			} else {
				ctrl.kicker.KickFromGame(username, sess.ServerID)
			}
		}
	}

	ipAddr, nErr := netip.ParseAddr(c.RemoteIP)
	if nErr != nil {
		ipAddr = netip.IPv4Unspecified()
	}
	ctrl.bans.ResetAttempts(ipAddr)
	ctrl.sessions.Register(username, c.SessionID)

	c.AccountID = account.ID
	c.Account = username
	c.State = client.StateAuthedLogin
	c.LastServer = account.LastServer

	_ = c.SendAsync(ServerLoginOK, func(w *network.PacketWriter) {
		w.WriteInt32(c.SessionKey.LoginOkID1)
		w.WriteInt32(c.SessionKey.LoginOkID2)
		w.WriteInt32(0x00)
		w.WriteInt32(0x00)
		w.WriteInt32(0x000003ea) // Protocol version target
		w.WriteInt32(0x00)
		w.WriteInt32(0x00)
		w.WriteInt32(0x00)
		for i := 0; i < 4; i++ {
			w.WriteInt32(0x00)
		}
	})
}

// readLoginBlocks copies the one or two RSA-encrypted credential blocks out of
// the pooled reader so they survive past the handler return.
func readLoginBlocks(r *network.PacketReader) (block1, block2 []byte, err error) {
	b1, err := r.ReadBytes(128)
	if err != nil {
		return nil, nil, err
	}
	block1 = append([]byte(nil), b1...)

	if r.ReadableBytes() >= 128 {
		b2, rErr := r.ReadBytes(128)
		if rErr != nil {
			return nil, nil, rErr
		}
		block2 = append([]byte(nil), b2...)
	}

	return block1, block2, nil
}

// decodeCredentials RSA-decrypts the credential blocks and extracts the
// username/password. block2 == nil selects the legacy single-block layout.
func decodeCredentials(key *crypto.ScrambledKey, block1, block2 []byte) (string, string, error) {
	var decrypted [256]byte

	part1, err := crypto.RSADecrypt(key, block1)
	if err != nil {
		return "", "", err
	}
	copy(decrypted[0:128], part1)

	var username, password string

	if block2 != nil {
		start := time.Now()
		part2, nErr := crypto.RSADecrypt(key, block2)
		metrics.RSADecryptDuration.Observe(time.Since(start).Seconds())
		if nErr != nil {
			return "", "", nErr
		}
		copy(decrypted[128:256], part2)

		username = cleanBytesToString(decrypted[0x4E:0x4E+50]) + cleanBytesToString(decrypted[0xCE:0xCE+14])
		password = cleanBytesToString(decrypted[0xDC : 0xDC+16])
	} else {
		username = cleanBytesToString(decrypted[0x5E : 0x5E+14])
		password = cleanBytesToString(decrypted[0x6C : 0x6C+16])
	}

	return strings.ToLower(username), password, nil
}

func getFailLabel(err error) string {
	switch {
	case errors.Is(err, service.ErrInvalidPassword):
		return "invalid_password"
	case errors.Is(err, service.ErrAccountNotFound):
		return "account_not_found"
	case errors.Is(err, service.ErrAccountBanned):
		return "account_banned"
	default:
		return "system_error"
	}
}

func cleanBytesToString(b []byte) string {
	start := 0
	end := len(b)

	for start < end && (b[start] == 0 || b[start] == ' ') {
		start++
	}
	for end > start && (b[end-1] == 0 || b[end-1] == ' ') {
		end--
	}

	if start >= end {
		return ""
	}

	return string(b[start:end])
}

func sendLoginFail(c *client.Client, reason byte) error {
	return c.SendAndCloseAsync(ServerLoginFail, func(w *network.PacketWriter) {
		w.WriteByte(reason)
	})
}

func getFailReasonFromError(err error) byte {
	switch {
	case errors.Is(err, service.ErrInvalidPassword):
		return 0x02
	case errors.Is(err, service.ErrAccountNotFound):
		return 0x01
	default:
		return 0x01
	}
}
