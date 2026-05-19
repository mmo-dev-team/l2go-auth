// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"crypto/rand"
	"encoding/binary"
)

// SessionKey contains the session identifiers used to validate a client's connection
// across different stages of the authentication and game session.
type SessionKey struct {
	LoginOkID1 int32 // First part of the LoginOk session ID
	LoginOkID2 int32 // Second part of the LoginOk session ID
	PlayOkID1  int32 // First part of the PlayOk session ID
	PlayOkID2  int32 // Second part of the PlayOk session ID
}

// GenerateSessionKey creates a new SessionKey with cryptographically secure random identifiers.
func GenerateSessionKey() (*SessionKey, error) {
	// We need 16 random bytes to fill four 32-bit integers (4 bytes * 4)
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}

	return &SessionKey{
		LoginOkID1: int32(binary.LittleEndian.Uint32(b[0:4])),
		LoginOkID2: int32(binary.LittleEndian.Uint32(b[4:8])),
		PlayOkID1:  int32(binary.LittleEndian.Uint32(b[8:12])),
		PlayOkID2:  int32(binary.LittleEndian.Uint32(b[12:16])),
	}, nil
}

// CheckLoginPair validates the provided login session identifiers.
func (s *SessionKey) CheckLoginPair(loginOK01, loginOK02 int32) bool {
	diff := (s.LoginOkID1 ^ loginOK01) | (s.LoginOkID2 ^ loginOK02)
	return diff == 0
}

// CheckPlayPair validates both login and play session identifiers.
func (s *SessionKey) CheckPlayPair(loginOK01, loginOK02, playOK01, playOK02 int32) bool {
	diff := (s.LoginOkID1 ^ loginOK01) |
		(s.LoginOkID2 ^ loginOK02) |
		(s.PlayOkID1 ^ playOK01) |
		(s.PlayOkID2 ^ playOK02)

	return diff == 0
}
