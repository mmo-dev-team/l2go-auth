// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/db"
	"github.com/mmo-dev-team/l2go-auth/internal/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrAccountNotFound = errors.New("account not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrAccountBanned   = errors.New("account banned")
	ErrIPBanned        = errors.New("ip banned")
	ErrAlreadyLoggedIn = errors.New("already logged in")
)

// Authenticator handles account authentication by verifying credentials against the database.
type Authenticator struct {
	queries    *db.Queries
	autoCreate bool
}

// NewAuthenticator creates a new Authenticator instance.
func NewAuthenticator(queries *db.Queries, autoCreate bool) *Authenticator {
	return &Authenticator{
		queries:    queries,
		autoCreate: autoCreate,
	}
}

// Authenticate verifies the username and password. If autoCreate is enabled, it creates the account if it doesn't exist.
func (a *Authenticator) Authenticate(ctx context.Context, username, password, ip string) (db.FindAccountRow, error) {
	start := time.Now()
	account, err := a.queries.FindAccount(ctx, username)
	metrics.DBFindAccount.Observe(time.Since(start).Seconds())

	if errors.Is(err, pgx.ErrNoRows) {
		if a.autoCreate {
			hashedPwd, id, cErr := a.createAccount(ctx, username, password, ip)
			if cErr != nil {
				return db.FindAccountRow{}, cErr
			}

			return db.FindAccountRow{
				ID:          id,
				Name:        username,
				Pwd:         hashedPwd,
				AccessLevel: 0,
				Banned:      false,
			}, nil
		}
		return db.FindAccountRow{}, ErrAccountNotFound
	}

	if err != nil {
		log.Error().Err(err).Str("username", username).Msg("Database connectivity error during lookup")
		return db.FindAccountRow{}, err
	}

	if err = bcrypt.CompareHashAndPassword([]byte(account.Pwd), []byte(password)); err != nil {
		return db.FindAccountRow{}, ErrInvalidPassword
	}

	if account.Banned || account.AccessLevel < 0 {
		return db.FindAccountRow{}, ErrAccountBanned
	}

	ipAddr, err := netip.ParseAddr(ip)
	var targetIP *netip.Addr
	if err == nil {
		targetIP = &ipAddr
	}

	_ = a.queries.UpdateAccountLastIPByName(ctx, db.UpdateAccountLastIPByNameParams{
		Name:   username,
		LastIp: targetIP,
	})

	return account, nil
}

// UpdateLastServer updates the ID of the last server the account connected to.
func (a *Authenticator) UpdateLastServer(ctx context.Context, username string, serverID int32) {
	_ = a.queries.UpdateAccountLastServer(ctx, db.UpdateAccountLastServerParams{
		Name:       username,
		LastServer: serverID,
	})
}

func (a *Authenticator) createAccount(ctx context.Context, username, password, ip string) (string, int64, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", 0, err
	}

	ipAddr, err := netip.ParseAddr(ip)
	var targetIP *netip.Addr
	if err == nil {
		targetIP = &ipAddr
	}

	hashedStr := string(hashed)

	start := time.Now()
	accountID, err := a.queries.RegisterAccount(ctx, db.RegisterAccountParams{
		Name:   username,
		Pwd:    hashedStr,
		LastIp: targetIP,
	})
	metrics.DBRegisterAccount.Observe(time.Since(start).Seconds())
	if err != nil {
		log.Error().Err(err).Str("username", username).Msg("Failed to execute account storage mutation")
		return "", 0, err
	}

	log.Debug().Str("username", username).Str("ip", ip).Msg("New account auto-registered via network")
	return hashedStr, accountID, nil
}
