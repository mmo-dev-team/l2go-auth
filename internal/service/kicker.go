// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

// Kicker defines methods for disconnecting accounts from the Login Server or Game Server.
type Kicker interface {
	KickAccount(username string)
	KickFromGame(username string, serverID int32)
	RequestCharacters(username string, accountID int64)
}

// KickManager implements the Kicker interface using lock-free, atomic stack-copied callbacks.
type KickManager struct {
	OnKickLS       func(username string)
	OnKickGS       func(username string, serverID int32)
	OnRequestChars func(username string, accountID int64)
}

// NewKickManager creates a new KickManager instance.
func NewKickManager() *KickManager {
	return &KickManager{}
}

// KickAccount executes the OnKickLS callback if it is set.
func (m *KickManager) KickAccount(username string) {
	fn := m.OnKickLS
	if fn != nil {
		fn(username)
	}
}

// KickFromGame executes the OnKickGS callback if it is set.
func (m *KickManager) KickFromGame(username string, serverID int32) {
	fn := m.OnKickGS
	if fn != nil {
		fn(username, serverID)
	}
}

// RequestCharacters executes the OnRequestChars callback if it is set.
func (m *KickManager) RequestCharacters(username string, accountID int64) {
	fn := m.OnRequestChars
	if fn != nil {
		fn(username, accountID)
	}
}
