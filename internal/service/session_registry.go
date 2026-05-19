// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"sync"
	"time"
)

const ShardCount = 64 // Must be a power of 2

// SessionInfo holds metadata about an active user session.
type SessionInfo struct {
	LoginTime         time.Time
	LastRejectionTime time.Time
	SessionID         int32
	ServerID          int32
}

// Shard reduces lock contention dramatically by isolating mutations.
type Shard struct {
	mu     sync.RWMutex
	active map[string]SessionInfo
}

// SessionRegistry manages active user sessions using concurrent sharding.
type SessionRegistry struct {
	shards [ShardCount]*Shard
}

// NewSessionRegistry initializes pre-allocated shards to prevent runtime map allocations.
func NewSessionRegistry() *SessionRegistry {
	sr := &SessionRegistry{}
	for i := 0; i < ShardCount; i++ {
		sr.shards[i] = &Shard{
			active: make(map[string]SessionInfo, 1024), // Pre-size based on expected load
		}
	}
	return sr
}

// TryRegister checks if a login attempt for the given username is allowed.
func (r *SessionRegistry) TryRegister(username string) (bool, bool) {
	shard := r.getShard(username)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	sess, ok := shard.active[username]
	if !ok {
		shard.active[username] = SessionInfo{
			SessionID: -1,
			LoginTime: now,
		}
		return false, true
	}

	if sess.SessionID == -1 && now.Sub(sess.LoginTime) < 5*time.Second {
		return false, false
	}

	if !sess.LastRejectionTime.IsZero() && now.Sub(sess.LastRejectionTime) < 30*time.Second {
		sess.LastRejectionTime = time.Time{}
		shard.active[username] = sess
		return true, true
	}

	sess.LastRejectionTime = now
	shard.active[username] = sess
	return false, false
}

// Register adds or updates an active session for the user.
func (r *SessionRegistry) Register(username string, sessionID int32) {
	shard := r.getShard(username)
	shard.mu.Lock()

	shard.active[username] = SessionInfo{
		SessionID: sessionID,
		ServerID:  0,
		LoginTime: time.Now(),
	}
	shard.mu.Unlock()
}

// Unregister removes an active session if the sessionID matches.
func (r *SessionRegistry) Unregister(username string, sessionID int32) bool {
	shard := r.getShard(username)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if sess, ok := shard.active[username]; ok && sess.SessionID == sessionID {
		delete(shard.active, username)
		return true
	}
	return false
}

// SetGS updates the current Game Server ID for an active session.
func (r *SessionRegistry) SetGS(username string, serverID int32) {
	shard := r.getShard(username)
	shard.mu.Lock()
	if sess, ok := shard.active[username]; ok {
		sess.ServerID = serverID
		shard.active[username] = sess
	}
	shard.mu.Unlock()
}

// Get retrieves session info safely using fine-grained read locks.
func (r *SessionRegistry) Get(username string) (SessionInfo, bool) {
	shard := r.getShard(username)
	shard.mu.RLock()
	sess, ok := shard.active[username]
	shard.mu.RUnlock()
	return sess, ok
}

// ClearServer clears connections linked to a dropped Game Server.
func (r *SessionRegistry) ClearServer(serverID int32) {
	for i := 0; i < ShardCount; i++ {
		shard := r.shards[i]
		shard.mu.Lock()
		for user, sess := range shard.active {
			if sess.ServerID == serverID {
				delete(shard.active, user)
			}
		}
		shard.mu.Unlock()
	}
}

func (r *SessionRegistry) getShard(username string) *Shard {
	var hash uint32 = 2166136261
	for i := 0; i < len(username); i++ {
		hash *= 16777619
		hash ^= uint32(username[i])
	}
	return r.shards[hash&(ShardCount-1)]
}
