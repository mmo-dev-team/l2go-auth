// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"context"
	"regexp"
	"testing"

	"github.com/mmo-dev-team/l2go-auth/internal/db"

	"github.com/pashagolub/pgxmock/v4"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	// 1. Create a mock database connection
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer mock.Close(context.Background())

	// 2. Initialize Authenticator with mock queries
	queries := db.New(mock)
	auth := NewAuthenticator(queries, false) // Disable autoCreate for this test

	username := "testuser"
	password := "testpass"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	t.Run("Successful authentication", func(t *testing.T) {
		// Expect FindAccount query. We use regexp.QuoteMeta to match the exact generated SQL string from sqlc.
		findAccountSQL := regexp.QuoteMeta("-- name: FindAccount :one\nSELECT a.id           AS id,\n       a.name         AS name,\n       a.pwd          AS pwd,\n       a.access_level AS access_level,\n       a.last_server  AS last_server,\n       a.banned       AS banned\nFROM l2auth.account a\nWHERE a.name = lower($1)\nLIMIT 1")

		mock.ExpectQuery(findAccountSQL).
			WithArgs(username).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "pwd", "access_level", "last_server", "banned"}).
				AddRow(int64(1), username, string(hashedPassword), int32(0), int32(0), false))

		// Expect UpdateAccountLastIPByName
		updateIPSQL := regexp.QuoteMeta("-- name: UpdateAccountLastIPByName :exec\nUPDATE l2auth.account\nSET\n    last_ip = $2,\n    modify_date = now()\nWHERE name = $1")

		mock.ExpectExec(updateIPSQL).
			WithArgs(username, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		account, err := auth.Authenticate(context.Background(), username, password, "127.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if account.Name != username {
			t.Errorf("expected username %s, got %s", username, account.Name)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("Invalid password", func(t *testing.T) {
		findAccountSQL := regexp.QuoteMeta("-- name: FindAccount :one\nSELECT a.id           AS id,\n       a.name         AS name,\n       a.pwd          AS pwd,\n       a.access_level AS access_level,\n       a.last_server  AS last_server,\n       a.banned       AS banned\nFROM l2auth.account a\nWHERE a.name = lower($1)\nLIMIT 1")

		mock.ExpectQuery(findAccountSQL).
			WithArgs(username).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "pwd", "access_level", "last_server", "banned"}).
				AddRow(int64(1), username, string(hashedPassword), int32(0), int32(0), false))

		_, err := auth.Authenticate(context.Background(), username, "wrongpass", "127.0.0.1")
		if err != ErrInvalidPassword {
			t.Errorf("expected ErrInvalidPassword, got %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}
