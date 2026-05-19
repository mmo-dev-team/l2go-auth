// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mmo-dev-team/l2go-auth/config"

	"github.com/mmo-dev-team/l2go-auth/internal/db"
	"github.com/mmo-dev-team/l2go-auth/internal/listener"
	"github.com/mmo-dev-team/l2go-auth/internal/middleware"
	"github.com/mmo-dev-team/l2go-auth/internal/service"
	"github.com/mmo-dev-team/l2go-auth/internal/session"

	"github.com/mmo-dev-team/l2go-auth/pkg/crypto"
	"github.com/mmo-dev-team/l2go-auth/pkg/database"
	_ "github.com/mmo-dev-team/l2go-auth/pkg/logger"

	"github.com/panjf2000/gnet/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Info().Msg("Starting L2 Login Server")

	// Start Prometheus metrics server
	go func() {
		log.Info().Str("port", "9090").Msg("Starting Prometheus metrics server")
		http.Handle("/metrics", promhttp.Handler())
		if hErr := http.ListenAndServe(":9090", nil); hErr != nil {
			log.Error().Err(hErr).Msg("Failed to start metrics server")
		}
	}()

	cfg := config.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start session garbage collection with a 120-second interval
	session.StartGC(120*time.Second, ctx.Done())

	cfgDB := cfg.Database
	dbPool, err := database.OpenPool(
		ctx,
		cfgDB.Host,
		cfgDB.Port,
		cfgDB.User,
		cfgDB.Pwd,
		cfgDB.Name,
		cfgDB.SSLMode,
		"l2auth",
		cfgDB.MaxConn,
		cfgDB.MaxConnIdleTime,
		cfgDB.IdleConn,
		cfgDB.MaxLifeTime,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	log.Info().Msg("Database connected")

	queries := db.New(dbPool)
	log.Info().Msg("DB pool initialized")

	serverList := service.NewServerList()
	authenticator := service.NewAuthenticator(queries, cfg.Account.AutoCreateAcc)
	sessions := service.NewSessionRegistry()
	bans := service.NewBanManager(context.Background(), queries, cfg.Account.AttemptsLoginCount)
	limiter := middleware.NewRateLimiter(5, time.Second) // Limit: 5 connections/sec per IP
	kickManager := service.NewKickManager()

	clientListener := listener.NewClientListener(
		queries,
		serverList,
		authenticator,
		sessions,
		bans,
		limiter,
		kickManager,
		30*time.Second, // 30-second client connection timeout
	)
	log.Info().Msg("Client listener initialized")

	gameServerListener := listener.NewGameServerListener(serverList, sessions, 30*time.Second) // 30-second game server connection timeout
	log.Info().Msg("Game server listener initialized")

	// Wire kick manager
	kickManager.OnKickLS = clientListener.KickAccount
	kickManager.OnKickGS = gameServerListener.KickAccount
	kickManager.OnRequestChars = gameServerListener.RequestCharacters

	// Initialize RSA key pool with 32 pre-generated keys
	crypto.InitRSAPool(32)
	log.Info().Msg("Cryptographic pool initialized")

	crypto.GenerateLoginBlowFishKeys()
	log.Info().Msg("Blowfish keys generated")

	options := []gnet.Option{
		gnet.WithMulticore(true),
		gnet.WithReuseAddr(true),
		gnet.WithReusePort(true),
		gnet.WithTicker(true),
		gnet.WithTCPNoDelay(gnet.TCPNoDelay),
		gnet.WithTCPKeepAlive(15 * time.Second),
		gnet.WithSocketRecvBuffer(1 << 20), // 1MB Socket receive buffer
		gnet.WithSocketSendBuffer(1 << 20), // 1MB Socket send buffer
		gnet.WithWriteBufferCap(4 << 20),   // 4MB Write buffer capacity
	}

	go func() {
		addr := "tcp://:" + cfg.ClientListenerPort
		if fErr := gnet.Run(clientListener, addr, options...); fErr != nil {
			log.Fatal().Err(fErr).Msg("Client listener error")
		}
	}()

	go func() {
		addr := "tcp://:" + cfg.GameServerListenerPort
		if fErr := gnet.Run(gameServerListener, addr, options...); fErr != nil {
			log.Fatal().Err(fErr).Msg("Game server listener error")
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	log.Info().Msg("Shutdown signal received, initiating graceful shutdown...")

	// Allow up to 30 seconds for graceful shutdown
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer sCancel()

	log.Info().Msg("Stopping client listener...")
	if clientListener.Engine != nil {
		if err = clientListener.Engine.Stop(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Error stopping client listener")
		}
	}

	log.Info().Msg("Stopping game server listener...")
	if gameServerListener.Engine != nil {
		if err = gameServerListener.Engine.Stop(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Error stopping game server listener")
		}
	}

	dbPool.Close()
	log.Info().Msg("Database connection closed")

	log.Info().Msg("Shutdown complete")
}
