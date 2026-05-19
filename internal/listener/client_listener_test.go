// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package listener

import (
	"net"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/mmo-dev-team/l2go-auth/internal/client"
	"github.com/mmo-dev-team/l2go-auth/internal/middleware"
	"github.com/mmo-dev-team/l2go-auth/internal/service"
	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
	"github.com/mmo-dev-team/l2go-auth/pkg/network"
)

// MockConn implements the subset of gnet.Conn required for testing OnOpen
type MockConn struct {
	gnet.Conn // panic on undefined methods
	ctx       any
	addr      net.Addr
}

func (m *MockConn) RemoteAddr() net.Addr {
	return m.addr
}

func (m *MockConn) SetContext(ctx any) {
	m.ctx = ctx
}

func (m *MockConn) Context() any {
	return m.ctx
}

func TestClientListener_OnOpen(t *testing.T) {
	// 1. Setup crypto dependencies
	crypto.InitRSAPool(2)
	crypto.GenerateLoginBlowFishKeys()

	// 2. Setup mock dependencies
	l := &ClientListener{
		bans:    &service.BanManager{}, // Reading from nil map in IsBanned is safe
		limiter: middleware.NewRateLimiter(10, time.Second),
		clients: make(map[gnet.Conn]*client.Client),
	}

	mockConn := &MockConn{
		addr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 12345,
		},
	}

	// 3. Execute the handler
	out, action := l.OnOpen(mockConn)

	// 4. Validate output action
	if action != gnet.None {
		t.Fatalf("Expected action gnet.None, got %v", action)
	}

	// 5. Validate packet structure (Init Packet)
	if out == nil {
		t.Fatal("Expected packet output, got nil")
	}

	// Read packet to verify structure
	r, err := network.GetPacketReader(out)
	if err != nil {
		t.Fatalf("Failed to create packet reader: %v", err)
	}
	defer network.PutPacketReader(r)

	// Verify Length Header
	length, _ := r.ReadUint16()
	if int(length) != len(out) {
		t.Errorf("Expected length %d, got %d", len(out), length)
	}

	// 6. Validate Context
	ctxClient, ok := mockConn.Context().(*client.Client)
	if !ok {
		t.Fatal("Expected context to contain *client.Client")
	}

	if ctxClient.State != client.StateConnected {
		t.Errorf("Expected client state %v, got %v", client.StateConnected, ctxClient.State)
	}
	if ctxClient.RemoteIP != "127.0.0.1" { // getIP strips the port
		t.Errorf("Expected RemoteIP '127.0.0.1', got %s", ctxClient.RemoteIP)
	}

	// 7. Validate connection map state
	l.clientMu.Lock()
	defer l.clientMu.Unlock()
	if _, exists := l.clients[mockConn]; !exists {
		t.Error("Expected connection to be stored in listener clients map")
	}
}
