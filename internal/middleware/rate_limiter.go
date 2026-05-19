// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package middleware

import (
	"sync"
	"time"
)

// RateLimiter implements a simple sliding-window rate limiting mechanism for IP addresses.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new RateLimiter with the specified limit and time window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	rl.startCleanup()
	return rl
}

func (r *RateLimiter) startCleanup() {
	go func() {
		// Periodically clean up expired entries every 10 minutes
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			r.cleanup()
		}
	}()
}

func (r *RateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for ip, attempts := range r.attempts {
		valid := attempts[:0]
		for _, t := range attempts {
			if now.Sub(t) <= r.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(r.attempts, ip)
		} else {
			r.attempts[ip] = valid
		}
	}
}

// IsLimited checks if the provided IP address has exceeded the rate limit.
func (r *RateLimiter) IsLimited(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	attempts := r.attempts[ip]

	count := 0
	for _, t := range attempts {
		if now.Sub(t) <= r.window {
			count++
		}
	}
	return count >= r.limit
}

// AddAttempt records a new attempt for the given IP address.
func (r *RateLimiter) AddAttempt(ip string) {
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

// Reset clears all recorded attempts for the specified IP address.
func (r *RateLimiter) Reset(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, ip)
}
