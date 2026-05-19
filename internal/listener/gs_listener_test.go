// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package listener

import (
	"net"
	"testing"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/service"

	"github.com/panjf2000/gnet/v2"
)

func TestGameServerListener_Lifecycle(t *testing.T) {
	serverList := service.NewServerList()
	sessions := service.NewSessionRegistry()
	gsl := NewGameServerListener(serverList, sessions, 0)

	mockConn := &MockConn{
		addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 7777},
	}

	t.Run("OnOpen sets up GameServerClient", func(t *testing.T) {
		_, action := gsl.OnOpen(mockConn)
		if action != gnet.None {
			t.Errorf("Expected action gnet.None, got %v", action)
		}

		gsc, ok := mockConn.Context().(*client.GameServerClient)
		if !ok {
			t.Fatal("Context should be *client.GameServerClient")
		}

		if gsc.RemoteIP != "10.0.0.1" {
			t.Errorf("Expected IP 10.0.0.1, got %s", gsc.RemoteIP)
		}
	})

	t.Run("OnClose unregisters server and clears sessions", func(t *testing.T) {
		gsc := mockConn.Context().(*client.GameServerClient)
		gsc.ServerID = 1

		// Register it in the server list
		serverList.Register(&service.Server{
			ID:   1,
			IP:   "127.0.0.1",
			Port: 7777,
		})

		// Add a session on this GS
		sessions.Register("player1", 123)
		sessions.SetGS("player1", 1)

		gsl.OnClose(mockConn, nil)

		// Check if server is gone from list
		snap := serverList.GetServers()
		if snap.Count != 0 {
			t.Error("Server should be unregistered after OnClose")
		}

		// Check if session on that server was cleared
		if _, ok := sessions.Get("player1"); ok {
			t.Error("Session on disconnected server should be cleared")
		}
	})
}
