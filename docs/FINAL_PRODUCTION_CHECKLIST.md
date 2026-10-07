# Final Production Checklist

## Architecture

- [x] Stateless API tier
- [x] PostgreSQL source of truth
- [x] Outbound-only node agent
- [x] Tenant-scoped resources
- [x] Durable command model
- [x] Explicit scaling boundary between control plane and node plane

## Security

- [x] Argon2 password hashing
- [x] High-entropy node credentials
- [x] Node credential hashes only at rest
- [x] Credential rotation
- [x] Bootstrap token required
- [x] Production startup requires session secret
- [x] Production startup requires secure cookies
- [x] Typed command allowlist
- [x] Command lease fencing
- [x] Bounded request/result payloads
- [x] Non-root API container
- [x] Security response headers
- [ ] mTLS between agent and control plane
- [ ] Distributed rate limiting

## Reliability

- [x] Database connection pre-ping
- [x] Connection recycling
- [x] Readiness endpoint
- [x] Liveness endpoint
- [x] PostgreSQL row-lock command leasing
- [x] Retry/expiry limits
- [x] Agent exponential backoff
- [x] Agent jitter
- [x] Idempotency keys
- [x] Additive database migrations
- [ ] Multi-region control plane
- [ ] Automated database failover

## Performance

- [x] Cursor pagination
- [x] Composite database indexes
- [x] Bounded page sizes
- [x] GZip responses
- [x] Async database access
- [x] Stable server cursors independent of heartbeat freshness
- [x] Agent empty-queue backoff
- [ ] Redis shared cache
- [ ] Dedicated command broker
- [ ] Read replicas
- [ ] Partitioned high-volume telemetry

## Operations

- [x] CI syntax validation
- [x] API import smoke test
- [x] Pagination regression test
- [x] ShellCheck
- [x] systemd validation
- [x] HAProxy validation
- [x] Production architecture documentation
- [x] Engineering review documentation
- [ ] Centralized metrics/trace backend
- [ ] SLO/error-budget automation
- [ ] Disaster-recovery restore drills

## Release rule

The current release is production-suitable for an early startup fleet when deployed behind TLS/WAF, with managed PostgreSQL, backups and monitoring.

Do not represent it as hyperscale-ready. When fleet size or traffic demands it, introduce Redis/distributed rate limiting, a dedicated command broker, telemetry storage and database partitioning as separate scaling stages.
