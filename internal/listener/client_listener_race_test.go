// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package listener

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mmo-dev-team/l2go-auth/internal/client"

	"github.com/panjf2000/gnet/v2"
)

// TestClientListener_ConcurrentFieldAccess reproduces the production contention
// that previously raced: the off-loop login worker publishes Account and touches
// LastActivity while the timeout sweep (OnTick) and KickAccount scan those same
// fields from other goroutines. With -race this fails on the unsynchronized
// version and passes once Account is mutex-guarded and LastActivity is atomic.
func TestClientListener_ConcurrentFieldAccess(t *testing.T) {
	const n = 64

	l := &ClientListener{
		clients: make(map[gnet.Conn]*client.Client),
		timeout: time.Hour, // large so OnTick never deletes; it still reads LastActivity
	}

	cls := make([]*client.Client, 0, n)
	for i := 0; i < n; i++ {
		conn := &MockConn{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000 + i}}
		cl := &client.Client{Conn: conn}
		cl.Touch()
		l.clients[conn] = cl
		cls = append(cls, cl)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: mimic processLogin publishing identity + OnTraffic touching activity.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := "user" + strconv.Itoa(id)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, cl := range cls {
					cl.SetAccount(name)
					cl.Touch()
				}
			}
		}(w)
	}

	// Readers: mimic KickAccount (scans AccountName) and OnTick (scans LastActivity).
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				l.KickAccount("no-such-account") // scans AccountName under clientMu, matches nothing
				l.OnTick()                       // scans LastActivityNanos under clientMu
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	if len(l.clients) != n {
		t.Fatalf("expected %d clients to remain, got %d", n, len(l.clients))
	}
}

func (m *MockConn) Close() error { return nil }
