// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package session

import (
	"sync"
	"testing"
	"time"
)

// TestSession_ConcurrentHandoff exercises the sharded handoff store under the
// real access pattern: client logins Put sessions while game-server validations
// ValidateAndDelete them and the GC sweep runs concurrently. Run with -race.
func TestSession_ConcurrentHandoff(t *testing.T) {
	stopGC := make(chan struct{})
	StartGC(10*time.Millisecond, stopGC)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Producers: simulate GameServerLogin handoff.
	for p := 0; p < 8; p++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			id := int32(base * 100000)
			for {
				select {
				case <-stop:
					return
				default:
				}
				Put(id, &Session{ExpiresAt: time.Now().Add(time.Minute), Account: "acc"})
				id++
			}
		}(p)
	}

	// Consumers: simulate GS validate consuming sessions by id.
	for c := 0; c < 8; c++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			id := int32(base * 100000)
			for {
				select {
				case <-stop:
					return
				default:
				}
				ValidateAndDelete(id)
				id++
			}
		}(c)
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(stopGC)
}
