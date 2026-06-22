// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/db"

	"github.com/pashagolub/pgxmock/v4"
)

func TestBanManager_Logic(t *testing.T) {
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer mock.Close(context.Background())

	// Expect initial load of bans
	mock.ExpectQuery("SELECT ip, expiry_date, reason FROM l2auth.ip_banned").
		WillReturnRows(pgxmock.NewRows([]string{"ip", "expiry_date", "reason"}))

	queries := db.New(mock)
	maxAttempts := 3
	bm := NewBanManager(context.Background(), queries, maxAttempts, 15*time.Minute)

	ip := netip.MustParseAddr("1.2.3.4")

	t.Run("Threshold banning", func(t *testing.T) {
		// 1st failure
		bm.RecordFailure(ip)
		if bm.IsBanned(ip) {
			t.Error("Should not be banned after 1st failure")
		}

		// 2nd failure
		bm.RecordFailure(ip)
		if bm.IsBanned(ip) {
			t.Error("Should not be banned after 2nd failure")
		}

		// 3rd failure - should trigger ban
		bm.RecordFailure(ip)
		if !bm.IsBanned(ip) {
			t.Error("Should be banned after 3rd failure")
		}
	})

	t.Run("Reset attempts", func(t *testing.T) {
		ip2 := netip.MustParseAddr("1.2.3.5")
		bm.RecordFailure(ip2)
		bm.RecordFailure(ip2)

		bm.ResetAttempts(ip2)

		// 3rd overall, but 1st after reset
		bm.RecordFailure(ip2)
		if bm.IsBanned(ip2) {
			t.Error("Should not be banned after reset and 1 new failure")
		}
	})
}
