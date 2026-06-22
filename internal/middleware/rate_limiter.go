// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package middleware

import (
	"net/netip"
	"sync"
	"time"
)

const rlShardCount = 64 // Must be a power of 2

// rlEntry is a fixed-window counter.
type rlEntry struct {
	windowStart int64 // Unix-nanos start of the current window
	count       int32
}

// rlShard isolates a subset of addresses under its own lock to cut contention.
type rlShard struct {
	entries map[netip.Addr]rlEntry
	mu      sync.Mutex
}

// RateLimiter implements a sharded fixed-window rate limiter keyed by IP address.
type RateLimiter struct {
	shards [rlShardCount]*rlShard
	window time.Duration
	limit  int32
}

// NewRateLimiter creates a new RateLimiter with the specified limit and time window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:  int32(limit),
		window: window,
	}
	for i := range rl.shards {
		rl.shards[i] = &rlShard{entries: make(map[netip.Addr]rlEntry, 1024)}
	}
	rl.startCleanup()
	return rl
}

// Allow records an attempt for ip and reports whether it is within the limit.
// It is safe for concurrent use and runs in O(1) with no steady-state allocations.
func (r *RateLimiter) Allow(ip netip.Addr) bool {
	now := time.Now().UnixNano()
	win := int64(r.window)

	sh := r.shardFor(ip)
	sh.mu.Lock()

	e := sh.entries[ip]
	if now-e.windowStart >= win {
		e.windowStart = now
		e.count = 0
	}

	if e.count >= r.limit {
		sh.mu.Unlock()
		return false
	}

	e.count++
	sh.entries[ip] = e
	sh.mu.Unlock()
	return true
}

func (r *RateLimiter) startCleanup() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			r.cleanup()
		}
	}()
}

// cleanup evicts addresses whose window has fully expired.
func (r *RateLimiter) cleanup() {
	cutoff := time.Now().UnixNano() - int64(r.window)
	for _, sh := range r.shards {
		sh.mu.Lock()
		for ip, e := range sh.entries {
			if e.windowStart < cutoff {
				delete(sh.entries, ip)
			}
		}
		sh.mu.Unlock()
	}
}

func (r *RateLimiter) shardFor(ip netip.Addr) *rlShard {
	b := ip.As16() // [16]byte by value — no allocation
	var h uint32 = 2166136261
	for i := 0; i < 16; i++ {
		h ^= uint32(b[i])
		h *= 16777619
	}
	return r.shards[h&(rlShardCount-1)]
}
