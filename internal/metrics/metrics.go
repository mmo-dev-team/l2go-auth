// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Connection metrics
	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "l2auth_active_connections",
		Help: "The current number of active client connections",
	})

	ConnectionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "l2auth_connections_total",
		Help: "The total number of client connections established",
	})

	// Login metrics
	LoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "l2auth_login_attempts_total",
		Help: "The total number of login attempts",
	}, []string{"status", "reason"})

	// Database latency
	DBQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "l2auth_db_query_duration_seconds",
		Help:    "Duration of database queries in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"query"})

	// Crypto latency
	RSADecryptDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "l2auth_rsa_decrypt_duration_seconds",
		Help:    "Duration of RSA decryption in seconds",
		Buckets: prometheus.DefBuckets,
	})
)

var (
	LoginSuccess        = LoginAttempts.WithLabelValues("success", "")
	LoginFailInvalidPwd = LoginAttempts.WithLabelValues("fail", "invalid_password")
	LoginFailNotFound   = LoginAttempts.WithLabelValues("fail", "account_not_found")
	LoginFailBanned     = LoginAttempts.WithLabelValues("fail", "account_banned")
	LoginFailSystem     = LoginAttempts.WithLabelValues("fail", "system_error")

	DBFindAccount     = DBQueryDuration.WithLabelValues("FindAccount")
	DBRegisterAccount = DBQueryDuration.WithLabelValues("RegisterAccount")
)
