// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package service

import (
	"sync"

	"github.com/rs/zerolog/log"
)

// Server represents a Game Server and its current state.
type Server struct {
	IP             string
	Port           int32
	ID             int32
	ServerType     int32
	MaxPlayers     int16
	CurrentPlayers int16
	Pvp            bool
	Brackets       bool
	Status         byte
}

// ServerSnapshot represents a fixed-size container for exporting server states.
type ServerSnapshot struct {
	Servers [MaxSupportedServers]Server
	Count   int
}

// MaxSupportedServers defines the upper bound of Game Servers in the cluster.
const MaxSupportedServers = 32

// ServerList manages the collection of registered Game Servers and account character counts.
type ServerList struct {
	mu         sync.RWMutex
	servers    [MaxSupportedServers]Server
	active     [MaxSupportedServers]bool
	charCounts map[string][MaxSupportedServers]byte
}

// NewServerList creates a new ServerList instance.
func NewServerList() *ServerList {
	return &ServerList{
		charCounts: make(map[string][MaxSupportedServers]byte),
	}
}

// Register adds or updates a Game Server in the list.
func (s *ServerList) Register(srv *Server) {
	if srv.ID < 0 || srv.ID >= MaxSupportedServers {
		log.Error().Int32("id", srv.ID).Msg("Server ID out of bounds, registration rejected")
		return
	}

	s.mu.Lock()
	s.servers[srv.ID] = *srv // Copy by value into the array
	s.active[srv.ID] = true
	s.mu.Unlock()

	log.Info().
		Int32("id", srv.ID).
		Str("ip", srv.IP).
		Int32("port", srv.Port).
		Msg("Server registered successfully")
}

// Unregister removes a Game Server from the list by its ID.
func (s *ServerList) Unregister(id int32) {
	if id < 0 || id >= MaxSupportedServers {
		return
	}

	s.mu.Lock()
	s.active[id] = false
	s.servers[id] = Server{} // Clear memory
	s.mu.Unlock()

	log.Info().Int32("id", id).Msg("Server unregistered")
}

// UpdateStatus updates specific properties of a Game Server based on infoType.
func (s *ServerList) UpdateStatus(id int32, infoType int, value int32) {
	if id < 0 || id >= MaxSupportedServers {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active[id] {
		return
	}

	srv := &s.servers[id]
	switch infoType {
	case 0x01: // Status (Up/Down/Busy)
		srv.Status = byte(value)
	case 0x02: // Server Type (Clock/Normal)
		srv.ServerType = value
	case 0x03: // Brackets (True/False)
		srv.Brackets = value == 1
	case 0x04: // Max Players capacity
		srv.MaxPlayers = int16(value)
	}
}

// AddPlayer increments the current player count for a server.
func (s *ServerList) AddPlayer(id int32) {
	if id < 0 || id >= MaxSupportedServers {
		return
	}

	s.mu.Lock()
	if s.active[id] {
		s.servers[id].CurrentPlayers++
	}
	s.mu.Unlock()
}

// RemovePlayer decrements the current player count for a server.
func (s *ServerList) RemovePlayer(id int32) {
	if id < 0 || id >= MaxSupportedServers {
		return
	}

	s.mu.Lock()
	if s.active[id] && s.servers[id].CurrentPlayers > 0 {
		s.servers[id].CurrentPlayers--
	}
	s.mu.Unlock()
}

// GetServers returns a snapshot of all active servers by value.
func (s *ServerList) GetServers() ServerSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var snap ServerSnapshot
	for i := 0; i < MaxSupportedServers; i++ {
		if s.active[i] {
			snap.Servers[snap.Count] = s.servers[i] // Value copy
			snap.Count++
		}
	}
	return snap
}

// SetCharCount records the number of characters an account has on a specific Game Server.
func (s *ServerList) SetCharCount(accountName string, serverID int32, count byte) {
	if serverID < 0 || serverID >= MaxSupportedServers {
		return
	}

	s.mu.Lock()
	counts := s.charCounts[accountName]
	counts[serverID] = count
	s.charCounts[accountName] = counts
	s.mu.Unlock()
}

// GetCharCounts retrieves character counts for all servers for a given account.
func (s *ServerList) GetCharCounts(accountName string) ([MaxSupportedServers]byte, bool) {
	s.mu.RLock()
	counts, ok := s.charCounts[accountName]
	s.mu.RUnlock()

	return counts, ok
}

// RemoveAccount clears cached character counts for a given account.
func (s *ServerList) RemoveAccount(accountName string) {
	s.mu.Lock()
	delete(s.charCounts, accountName)
	s.mu.Unlock()
}
