// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package middleware

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// oldRateLimiter reproduces the pre-fix implementation.
type oldRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func (r *oldRateLimiter) IsLimited(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	count := 0
	for _, t := range r.attempts[ip] {
		if now.Sub(t) <= r.window {
			count++
		}
	}
	return count >= r.limit
}

func (r *oldRateLimiter) AddAttempt(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	attempts := r.attempts[ip]
	valid := attempts[:0]
	for _, t := range attempts {
		if now.Sub(t) <= r.window {
			valid = append(valid, t)
		}
	}
	r.attempts[ip] = append(valid, now)
}

// BenchmarkRateLimit_Old mimics OnOpen pre-fix: getIP returns a string.
func BenchmarkRateLimit_Old(b *testing.B) {
	r := &oldRateLimiter{attempts: make(map[string][]time.Time), limit: 1 << 30, window: time.Second}
	tcp := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 5000}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := tcp.IP.String() // OnOpen derived the key as a string
		if !r.IsLimited(ip) {
			r.AddAttempt(ip)
		}
	}
}

// BenchmarkRateLimit_New is the current path: parse once to netip.Addr, single
// atomic Allow (prune+count+record under one shard lock).
func BenchmarkRateLimit_New(b *testing.B) {
	r := NewRateLimiter(1<<30, time.Second)
	addr := netip.AddrFrom4([4]byte{192, 168, 1, 50})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Allow(addr)
	}
}

// BenchmarkRateLimit_OldParallel / NewParallel show contention behavior across
// many source IPs (global mutex vs 64 shards).
func BenchmarkRateLimit_OldParallel(b *testing.B) {
	r := &oldRateLimiter{attempts: make(map[string][]time.Time), limit: 1 << 30, window: time.Second}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		n := 0
		for pb.Next() {
			ip := net.IPv4(10, 0, byte(n>>8), byte(n)).String()
			if !r.IsLimited(ip) {
				r.AddAttempt(ip)
			}
			n++
		}
	})
}

func BenchmarkRateLimit_NewParallel(b *testing.B) {
	r := NewRateLimiter(1<<30, time.Second)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		n := 0
		for pb.Next() {
			r.Allow(netip.AddrFrom4([4]byte{10, 0, byte(n >> 8), byte(n)}))
			n++
		}
	})
}
