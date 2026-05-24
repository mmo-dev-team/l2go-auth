# l2go-auth

[![CI](https://github.com/mmo-dev-team/l2go-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/mmo-dev-team/l2go-auth/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/mmo-dev-team/l2go-auth)](https://goreportcard.com/report/github.com/mmo-dev-team/l2go-auth)
[![Security: Fuzzing](https://img.shields.io/badge/Security-Fuzz_Tested-brightgreen?style=flat-square&logo=go)](#testing)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mmo-dev-team/l2go-auth?style=flat-square&logo=go)](https://go.dev/)
[![Docker Pulls](https://img.shields.io/docker/pulls/mmodevteam/l2go-auth?style=flat-square&logo=docker)](https://hub.docker.com/r/mmodevteam/l2go-auth)
[![Release](https://img.shields.io/github/v/release/mmo-dev-team/l2go-auth?style=flat-square&logo=github)](https://github.com/mmo-dev-team/l2go-auth/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/mmo-dev-team/l2go-auth.svg)](https://pkg.go.dev/github.com/mmo-dev-team/l2go-auth)
[![License](https://img.shields.io/github/license/mmo-dev-team/l2go-auth?style=flat-square)](LICENSE)

A high-performance Lineage II Login Server written in **Go**.

## Overview

`l2go-auth` is designed to be a lightweight, secure. It focuses on high throughput, minimal memory footprint, and
production-grade reliability using an event-driven networking model.

## Key Features

* **High Performance:** Powered by [gnet](https://github.com/panjf2000/gnet), an event-loop networking framework (
  epoll/kqueue). Capable of handling tens of thousands of concurrent connections with extremely low overhead.
* **Security First:**
    * **Fuzz Tested:** The packet parser has been stress-tested with over 7 million iterations of random data (Go
      Fuzzing) to ensure zero panics from malformed packets.
    * **Anti-Bruteforce:** Integrated `BanManager` that tracks failed attempts and automatically jails IPs.
    * **Rate Limiting:** Built-in TCP connection rate limiting to protect against connection flood attacks.
* **Optimized Cryptography:**
    * Pre-generated **RSA Key Pool** (32 keys) to prevent CPU spikes during mass login events.
    * Custom Blowfish implementation compliant with the L2 protocol.
* **Modern Database Stack:** Uses [sqlc](https://sqlc.dev/) for compile-time safe, zero-reflection SQL queries
  over [pgx](https://github.com/jackc/pgx) (PostgreSQL).
* **Observability:** Built-in [Prometheus](https://prometheus.io/) exporter. Monitor logins, active sessions, and
  database latency in real-time with Grafana.
* **Scalable Architecture:** Sharded Session Registry (64 shards) to minimize lock contention in multi-threaded
  environments.
* **Session Management:**
    * **Integrated Kicker:** Gracefully handles concurrent login attempts by disconnecting existing sessions across Login and Game Servers.
    * **Smart Rejection:** Prevents login spam and manages session handovers between LS and GS.

## Getting Started

### Prerequisites

* Go 1.26 or higher
* PostgreSQL instance
* (Optional) Prometheus for metrics

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mmo-dev-team/l2go-auth.git
   cd l2go-auth
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Generate database code:
    ```bash
    # Make sure you have sqlc installed (go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest)
    go generate ./...
    ```

4. Setup the database:
    ```bash
    Execute the schema found in `schemas/l2auth.sql` on your PostgreSQL database.
    ```

### Configuration

The application is configured using environment variables. You can find a template in `.env.example`.

| Variable | Description | Default |
|----------|-------------|---------|
| `GAMESERVER_LISTENER_PORT` | Port for Game Server connections | `9014` |
| `CLIENT_LISTENER_PORT` | Port for Client (Game) connections | `2106` |
| `DB_HOST` | PostgreSQL Host | `localhost` |
| `DB_PORT` | PostgreSQL Port | `5432` |
| `DB_USER` | Database User | `l2auth` |
| `DB_PWD` | Database Password | `l2auth` |
| `DB_NAME` | Database Name | `l2auth` |
| `DB_SSL_MODE` | SSL Mode (disable, require, etc.) | `disable` |
| `DB_MAX_CONN` | Maximum number of open connections | `20` |
| `DB_IDLE_CONN` | Maximum number of idle connections | `10` |
| `DB_MAX_LIFETIME` | Maximum amount of time a connection may be reused (seconds) | `300` |
| `DB_MAX_CONN_IDLE_TIME` | Maximum amount of time a connection may be idle (seconds) | `60` |
| `ATTEMPTS_LOGIN_COUNT` | Failed login attempts before IP ban | `5` |
| `AUTO_CREATE_ACCOUNT` | Enable/Disable auto account creation | `true` |
| `LOGIN_RATE_LIMIT` | Max login requests per second | `10` |

### Running the Server

#### Locally

1. Set the environment variables (e.g., using an `.env` file or export).
2. Run the server:
    ```bash
    go run cmd/main.go
    ```

#### Docker

1. Build the image:
   ```bash
   docker build -t l2go-auth .
   ```

2. Run the container:
   ```bash
   docker run -d \
     --name l2go-auth \
     -p 2106:2106 \
     -p 9014:9014 \
     -p 9090:9090 \
     --env-file .env \
     l2go-auth
   ```

#### Docker Compose

This is the easiest way to start the server along with a PostgreSQL database:

1. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```

2. Start the services:
   ```bash
   docker-compose up -d
   ```

This will:
* Start a PostgreSQL 17 database.
* Automatically apply the schema from `schemas/l2auth.sql`.
* Build and start the `l2go-auth` server.
* Expose all necessary ports (2106, 9014, 9090).

## Testing

The project follows a 3-layer testing strategy:

1. **Unit & Fuzz Tests:** `go test ./pkg/network ./internal/crypto`
2. **Mock Network Tests:** `go test ./internal/listener`
3. **Database Integration Tests:** `go test ./internal/service`

To run all tests:

```bash
go test -v ./...
```

## Monitoring

Metrics are exposed at `http://localhost:9090/metrics` by default.
Key metrics include:

* `l2auth_active_connections`: Current active TCP sessions.
* `l2auth_connections_total`: Total number of established connections.
* `l2auth_login_attempts_total`: Success/Failure stats with reason labels.
* `l2auth_db_query_duration_seconds`: Histogram of database query latency.
* `l2auth_rsa_decrypt_duration_seconds`: Histogram of RSA decryption performance.

## Contributing

Contributions are welcome! Adding new features, or fixing bugs, feel free to open a Pull Request.

## License

This project is open-source and available under the [Mozilla Public License 2.0 (MPL 2.0)](LICENSE).