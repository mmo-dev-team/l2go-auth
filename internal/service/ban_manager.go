// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/db"

	"github.com/rs/zerolog/log"
)

// BanManager manages IP-based bans and login attempt tracking to prevent brute-force attacks.
type BanManager struct {
	queries     *db.Queries
	maxAttempts int
	ctx         context.Context
	mu          sync.RWMutex
	ipBans      map[netip.Addr]time.Time
	attempts    map[netip.Addr]int
}

// NewBanManager creates a new BanManager and loads existing active bans from the database.
func NewBanManager(ctx context.Context, queries *db.Queries, maxAttempts int) *BanManager {
	bm := &BanManager{
		queries:     queries,
		maxAttempts: maxAttempts,
		ctx:         ctx,
		ipBans:      make(map[netip.Addr]time.Time),
		attempts:    make(map[netip.Addr]int),
	}

	// Load active bans from DB on startup with a 10s timeout
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	bans, err := queries.GetActiveIPBans(initCtx)
	if err == nil {
		for _, ban := range bans {
			bm.ipBans[ban.Ip] = ban.ExpiryDate
		}
	}

	return bm
}

// IsBanned checks if a given IP address is currently banned. Loopback (127.0.0.1 /
// ::1) is never banned — it is the host itself (local tools, load tests) and must not
// be able to lock itself out via the brute-force throttle.


// IsBanned checks if a given IP address is currently banned.
// Loopback (127.0.0.1 / ::1) is never banned.
func (m *BanManager) IsBanned(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return false
	}

	m.mu.RLock()
	expiry, ok := m.ipBans[ip]
	m.mu.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(expiry) {
		m.mu.Lock()
		expiry, ok = m.ipBans[ip]
		if ok && time.Now().After(expiry) {
			delete(m.ipBans, ip)
			m.mu.Unlock()

			go func(targetIP netip.Addr) {
				ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
				defer cancel()
				_ = m.queries.RemoveIPBan(ctx, targetIP)
			}(ip)

			return false
		}
		m.mu.Unlock()
	}

	return true
}

// RecordFailure increments the failure count for an IP and applies a ban if the threshold is reached.
func (m *BanManager) RecordFailure(ip netip.Addr) {
	if ip.IsLoopback() {
		return // never throttle/ban the host itself
	}

	m.mu.Lock()

	m.attempts[ip]++
	count := m.attempts[ip]

	if count >= m.maxAttempts {
		expiry := time.Now().Add(15 * time.Minute)
		m.ipBans[ip] = expiry
		delete(m.attempts, ip)
		m.mu.Unlock()

		go func(targetIP netip.Addr, banExpiry time.Time) {
			ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
			defer cancel()
			_ = m.queries.AddIPBan(ctx, db.AddIPBanParams{
				Ip:         targetIP,
				ExpiryDate: banExpiry,
				Reason:     "Too many login attempts",
			})
		}(ip, expiry)

		log.Warn().Stringer("ip", ip).Msg("IP address shifted to banned pool")
		return
	}

	m.mu.Unlock()
}

// ResetAttempts clears the failure count for a successfully authenticated IP.
func (m *BanManager) ResetAttempts(ip netip.Addr) {
	m.mu.Lock()
	delete(m.attempts, ip)
	m.mu.Unlock()
}
