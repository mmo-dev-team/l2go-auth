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

// Session represents a temporary authentication session for account handoff to a Game Server.
type Session struct {
	ExpiresAt time.Time
	Key       *crypto.SessionKey
	Account   string
	AccountID int64
	ServerID  int32
}

var (
	sessions sync.Map
)

// Put stores a session by its ID.
func Put(id int32, session *Session) {
	sessions.Store(id, session)
}

// ValidateAndDelete retrieves and removes a session by its ID if it exists and is not expired.
func ValidateAndDelete(id int32) (*Session, bool) {
	val, ok := sessions.Load(id)
	if !ok {
		return nil, false
	}

	session := val.(*Session)

	if time.Now().After(session.ExpiresAt) {
		sessions.Delete(id)
		return nil, false
	}

	sessions.Delete(id)
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

				sessions.Range(func(key, value interface{}) bool {
					session := value.(*Session)
					if now.After(session.ExpiresAt) {
						sessions.Delete(key)
					}
					return true
				})

			case <-stop:
				return
			}
		}
	}()
}
