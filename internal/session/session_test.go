// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package session

import (
	"testing"
	"time"
)

// Negative ids keep these cases isolated from the concurrent race test.
func TestSession_PutValidateDelete(t *testing.T) {
	const id = -1001
	Put(id, &Session{ExpiresAt: time.Now().Add(time.Minute), Account: "acc", ServerID: 7})

	sess, ok := ValidateAndDelete(id)
	if !ok {
		t.Fatal("expected a live session to validate")
	}
	if sess.Account != "acc" || sess.ServerID != 7 {
		t.Fatalf("unexpected session payload: %+v", sess)
	}

	if _, ok := ValidateAndDelete(id); ok {
		t.Error("expected the session to be gone after the first validate")
	}
}

func TestSession_Expired(t *testing.T) {
	const id = -1002
	Put(id, &Session{ExpiresAt: time.Now().Add(-time.Second), Account: "old"})

	if _, ok := ValidateAndDelete(id); ok {
		t.Error("expected an expired session to be rejected")
	}
	if _, ok := ValidateAndDelete(id); ok {
		t.Error("expected the expired session to also be removed")
	}
}

func TestSession_Missing(t *testing.T) {
	if _, ok := ValidateAndDelete(-999999); ok {
		t.Error("expected missing id to report not found")
	}
}
