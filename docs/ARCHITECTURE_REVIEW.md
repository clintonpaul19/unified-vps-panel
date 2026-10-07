# Unified VPS architecture review

## Architecture breakdown

Unified VPS currently contains two distinct planes.

### Node-local plane

Browser/CLI -> `panel/app.py` -> SQLite + Xray + Hysteria + Linux users + systemd + HAProxy + NGINX + firewall + backup/certificate operations.

`panel/app.py` is a privileged node-management monolith. It owns HTTP routing, HTML rendering, authentication, persistence, telemetry, proxy configuration and Linux process/account orchestration.

### Scalable control plane

Browser -> FastAPI -> PostgreSQL -> durable commands/audit -> outbound node agent -> fixed local handlers.

This is the correct boundary for multi-tenant SaaS. The browser never receives a shell-execution API and the node agent never accepts arbitrary shell text.

## End-to-end data flow

### Local account creation
1. Browser or CLI submits an account request.
2. The local panel validates input.
3. The panel mutates Xray, Hysteria or the Linux account.
4. SQLite records desired account metadata and usage baselines.
5. The dashboard renders connection URIs from persisted state.

The important limitation is transactional: Linux/Xray/Hysteria and SQLite are separate systems. A true atomic commit is impossible across them.

### Control-plane command
1. Operator authenticates to the control plane.
2. Organization context is resolved from membership.
3. A typed command is committed to PostgreSQL with an idempotency key.
4. The node agent polls and receives a short lease.
5. The agent maps the command type to an allowlisted handler.
6. The handler executes locally.
7. The agent reports the result.
8. The control plane retains the command and audit event.

## Critical problem areas

### Privileged monolith
`panel/app.py` is roughly 1,600 lines and crosses presentation, persistence and privileged system operations.

### SQLite contention
Opening SQLite and running schema migrations from every connection created unnecessary lock and latency overhead. The node panel now initializes schema once, enables WAL and sets a busy timeout.

### Duplicate lifecycle logic
Enable, disable, renew and delete existed in both single-account and bulk paths. The node panel now routes these actions through `apply_user_action()`.

### Process-spawn amplification
Dashboard requests previously launched many separate `systemctl`, `ss` and `ps` processes. Service status is now batched and process ownership is read from `/proc`.

### Blocking maintenance requests
Backups, restores, certificate renewal and Speedtest can occupy HTTP threads for long periods. These should become local asynchronous jobs.

### External-side-effect consistency
An Xray restart or `useradd` can succeed while a database transaction fails. The current code compensates where practical; the longer-term answer is reconciliation from a desired-state model.

### Unbounded retention
Audit events and telemetry need explicit retention/partitioning policies before high-volume deployments.

### Polling scale
One agent heartbeat/poll loop per VPS does not scale linearly to a very large fleet. The agent now uses jitter and exponential backoff on failures. Production should move command delivery to Redis/NATS/SQS-style infrastructure or long polling.

### Bootstrap/session hardening
The control plane now rejects repeat bootstrap, supports an optional bootstrap token, uses Secure cookies in production, and scopes resources to an explicit organization when a user has multiple memberships.

### Schema lifecycle
Production control-plane startup no longer runs SQLAlchemy `create_all()` unless explicitly enabled. The database schema is now a deploy-time concern.

## Refactoring strategy

Phase 1 completed:
- hot-path SQLite optimization
- consolidated local account actions
- reduced subprocess amplification
- bounded control-plane payloads
- organization scoping
- command leases and retry attempts
- token rotation
- agent backoff and correct uptime reporting
- explicit development-only schema creation

Phase 2:
- split `panel/app.py` into auth, database, system, account and route modules without changing the current HTTP contract
- move Speedtest/certificate/backup operations to a local job executor
- add structured logging and Prometheus/OpenTelemetry metrics

Phase 3:
- Redis-backed rate limiting
- distributed command workers
- PostgreSQL migrations/read replicas
- object storage for backups
- centralized telemetry

Phase 4:
- mTLS or short-lived node credentials
- desired-state reconciliation
- partitioned high-volume telemetry
- edge WAF/rate limiting
- per-organization usage and billing boundaries

## Preserve-existing-functionality rule

The refactor must not remove SSH, VLESS, VMess, Trojan, Hysteria 2, WebSocket/WSS transports, HAProxy multiplexing, account expiry, usage accounting, backups, certificates, watchdog, Fail2Ban, Speedtest, CLI management or the first-run administrator setup. The purpose of the refactor is to change internal boundaries, not user-visible capabilities.