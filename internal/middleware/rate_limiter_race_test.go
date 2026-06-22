// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package middleware

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestRateLimiter_ConcurrentAllow hammers Allow from many goroutines across a mix
// of addresses (same-shard contention and cross-shard) to verify the single-lock.
func TestRateLimiter_ConcurrentAllow(t *testing.T) {
	rl := NewRateLimiter(5, 50*time.Millisecond)

	addrs := make([]netip.Addr, 0, 32)
	for i := 0; i < 32; i++ {
		addrs = append(addrs, netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i)}))
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			i := seed
			for {
				select {
				case <-stop:
					return
				default:
				}
				rl.Allow(addrs[i%len(addrs)])
				i++
			}
		}(g)
	}

	// Concurrent cleanup sweeps racing the Allow calls.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rl.cleanup()
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestRateLimiter_LimitEnforced confirms the fixed window admits exactly `limit`.
func TestRateLimiter_LimitEnforced(t *testing.T) {
	rl := NewRateLimiter(5, time.Hour) // long window: no reset during the test
	ip := netip.MustParseAddr("203.0.113.7")

	const callers = 50
	var allowed int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow(ip) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != 5 {
		t.Fatalf("expected exactly 5 allowed within the window, got %d", allowed)
	}
}
