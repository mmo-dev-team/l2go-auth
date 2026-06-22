// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package session

import (
	"sync"
	"time"

	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
)

const sessionShardCount = 64 // Must be a power of 2

// Session represents a temporary authentication session for account handoff to a Game Server.
type Session struct {
	ExpiresAt time.Time
	Key       *crypto.SessionKey
	Account   string
	AccountID int64
	ServerID  int32
}

// shard isolates a subset of sessions under its own lock.
type shard struct {
	sessions map[int32]*Session
	mu       sync.Mutex
}

var shards [sessionShardCount]*shard

func init() {
	for i := range shards {
		shards[i] = &shard{sessions: make(map[int32]*Session, 256)}
	}
}

func shardFor(id int32) *shard {
	return shards[uint32(id)&(sessionShardCount-1)]
}

// Put stores a session by its ID.
func Put(id int32, session *Session) {
	sh := shardFor(id)
	sh.mu.Lock()
	sh.sessions[id] = session
	sh.mu.Unlock()
}

// ValidateAndDelete retrieves and removes a session by its ID if it exists and is not expired.
func ValidateAndDelete(id int32) (*Session, bool) {
	sh := shardFor(id)
	sh.mu.Lock()
	session, ok := sh.sessions[id]
	if ok {
		delete(sh.sessions, id)
	}
	sh.mu.Unlock()

	if !ok || time.Now().After(session.ExpiresAt) {
		return nil, false
	}
	return session, true
}

// StartGC starts a background garbage collection loop to remove expired sessions.
func StartGC(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-t.C:
				now := time.Now()
				for _, sh := range shards {
					sh.mu.Lock()
					for id, session := range sh.sessions {
						if now.After(session.ExpiresAt) {
							delete(sh.sessions, id)
						}
					}
					sh.mu.Unlock()
				}
			case <-stop:
				return
			}
		}
	}()
}
