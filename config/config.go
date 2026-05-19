// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package config

import (
	"os"
	"strconv"

	"github.com/rs/zerolog/log"
)

// Config holds the application configuration loaded from environment variables.
type Config struct {
	Database               *Database
	Account                *Account
	GameServerListenerPort string
	ClientListenerPort     string
}

// Database holds database connection and pooling settings.
type Database struct {
	Host            string
	User            string
	Pwd             string
	Name            string
	SSLMode         string
	Port            string
	MaxConn         int
	IdleConn        int
	MaxLifeTime     int
	MaxConnIdleTime int
}

// Account holds authentication and account creation settings.
type Account struct {
	AttemptsLoginCount int
	AutoCreateAcc      bool
}

// New creates a new Config instance by loading values from environment variables.
func New() *Config {
	c := &Config{
		GameServerListenerPort: os.Getenv("GAMESERVER_LISTENER_PORT"),
		ClientListenerPort:     os.Getenv("CLIENT_LISTENER_PORT"),
		Database:               getDatabaseSettings(),
		Account:                getAccountSettings(),
	}
	log.Info().Msg("Configuration loaded successfully")
	return c
}

func getAccountSettings() *Account {
	return &Account{
		AttemptsLoginCount: mustAtoi("ATTEMPTS_LOGIN_COUNT"),
		AutoCreateAcc:      mustBool("AUTO_CREATE_ACCOUNT"),
	}
}

func getDatabaseSettings() *Database {
	return &Database{
		Host:            os.Getenv("DB_HOST"),
		User:            os.Getenv("DB_USER"),
		Pwd:             os.Getenv("DB_PWD"),
		Port:            os.Getenv("DB_PORT"),
		Name:            os.Getenv("DB_NAME"),
		SSLMode:         os.Getenv("DB_SSL_MODE"),
		MaxConn:         mustAtoi("DB_MAX_CONN"),
		IdleConn:        mustAtoi("DB_IDLE_CONN"),
		MaxLifeTime:     mustAtoi("DB_MAX_LIFETIME"),
		MaxConnIdleTime: mustAtoi("DB_MAX_CONN_IDLE_TIME"),
	}
}

func mustAtoi(key string) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Invalid integer value")
	}
	return v
}

func mustBool(key string) bool {
	v, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Invalid boolean value")
	}
	return v
}
