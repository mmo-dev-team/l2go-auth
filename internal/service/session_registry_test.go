// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"fmt"
	"sync"
	"testing"
)

func TestSessionRegistry_Concurrency(t *testing.T) {
	registry := NewSessionRegistry()
	username := "race_user"

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make(chan bool, goroutines)

	// Simulate 100 simultaneous login attempts for the same user
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, allowed := registry.TryRegister(username)
			results <- allowed
		}()
	}

	wg.Wait()
	close(results)

	allowedCount := 0
	for allowed := range results {
		if allowed {
			allowedCount++
		}
	}

	// Only ONE attempt should be allowed to register the initial "waiting" state
	if allowedCount != 1 {
		t.Errorf("Expected exactly 1 allowed registration, got %d", allowedCount)
	}
}

func TestSessionRegistry_Sharding(t *testing.T) {
	registry := NewSessionRegistry()

	// Test that different users go to different shards (statistically)
	shardsUsed := make(map[int]bool)
	for i := 0; i < 1000; i++ {
		user := fmt.Sprintf("user_%d", i)
		shard := registry.getShard(user)

		// Find shard index
		for idx, s := range registry.shards {
			if s == shard {
				shardsUsed[idx] = true
				break
			}
		}
	}

	if len(shardsUsed) < 10 {
		t.Errorf("Poor sharding distribution: only %d shards used for 1000 users", len(shardsUsed))
	}
}
