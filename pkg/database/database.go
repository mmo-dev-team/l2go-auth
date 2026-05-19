// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenPool establishes a connection pool to a PostgreSQL database using the provided configuration.
// It configures connection limits, lifetimes, and performance-related runtime parameters.
func OpenPool(
	ctx context.Context,
	host,
	port,
	user,
	pwd,
	name,
	sslMode,
	appName string,
	maxConnections,
	maxConnIdleTime,
	idleConnections,
	maxLifeConnections int,
) (*pgxpool.Pool, error) {
	connStr := "host=" + host +
		" port=" + port +
		" user=" + user +
		" password=" + pwd +
		" dbname=" + name +
		" sslmode=" + sslMode

	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, errors.Join(errors.New("failed to parse"), err)
	}

	cfg.MaxConns = int32(maxConnections)
	cfg.MinConns = int32(idleConnections)
	cfg.MaxConnLifetime = time.Duration(maxLifeConnections) * time.Minute
	cfg.MaxConnIdleTime = time.Duration(maxConnIdleTime) * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second // Frequency of background health checks
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	cfg.ConnConfig.RuntimeParams["application_name"] = appName
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "3s"                         // Max time to wait for a lock
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30s"                   // Max time for statement execution
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "30s" // Max time a session can be idle in a transaction

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.Join(errors.New("create pool"), err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second) // Timeout for the initial database ping
	defer cancel()
	if err = pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, errors.Join(errors.New("database ping failed"), err)
	}

	return pool, nil
}
