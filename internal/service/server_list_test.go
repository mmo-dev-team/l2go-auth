// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"testing"
)

func TestServerList_UpdateStatus(t *testing.T) {
	sl := NewServerList()
	srv := &Server{
		ID:         1,
		IP:         "127.0.0.1",
		Port:       7777,
		MaxPlayers: 100,
	}
	sl.Register(srv)

	t.Run("Update Current Players", func(t *testing.T) {
		sl.UpdateStatus(1, InfoTypeCurrentPlayers, 50)
		snap := sl.GetServers()
		found := false
		for i := 0; i < snap.Count; i++ {
			if snap.Servers[i].ID == 1 {
				found = true
				if snap.Servers[i].CurrentPlayers != 50 {
					t.Errorf("Expected 50 players, got %d", snap.Servers[i].CurrentPlayers)
				}
			}
		}
		if !found {
			t.Error("Server not found in snapshot")
		}
	})

	t.Run("Update Status", func(t *testing.T) {
		sl.UpdateStatus(1, InfoTypeStatus, 2) // Busy
		snap := sl.GetServers()
		for i := 0; i < snap.Count; i++ {
			if snap.Servers[i].ID == 1 {
				if snap.Servers[i].Status != 2 {
					t.Errorf("Expected status 2, got %d", snap.Servers[i].Status)
				}
			}
		}
	})

	t.Run("Update with invalid ID does nothing", func(t *testing.T) {
		sl.UpdateStatus(99, InfoTypeCurrentPlayers, 10)
		snap := sl.GetServers()
		for i := 0; i < snap.Count; i++ {
			if snap.Servers[i].ID == 1 {
				if snap.Servers[i].CurrentPlayers != 50 {
					t.Errorf("Server 1 players changed unexpectedly")
				}
			}
		}
	})
}
