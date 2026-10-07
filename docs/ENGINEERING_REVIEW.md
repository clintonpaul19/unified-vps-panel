# Senior Engineering Review

Review target: Unified VPS control plane and node-agent architecture on main.

## Critical findings found and fixed

### 1. Empty command queue polling could hot-loop

The agent previously requested /commands/next repeatedly with no delay when the queue was empty. At fleet scale this could create unnecessary API and PostgreSQL load.

Status: fixed.

The agent now applies exponential backoff with jitter for empty queues and transport failures, capped at a bounded delay.

### 2. Bootstrap endpoint could be exposed when BOOTSTRAP_TOKEN was empty

The earlier condition only validated the token when a token happened to be configured. A production deployment with an empty value could therefore reach the bootstrap logic.

Status: fixed.

Production configuration now fails startup without BOOTSTRAP_TOKEN, and the endpoint always requires a configured token.

### 3. Stale command execution required fencing

A leased command can be reclaimed after an agent disappears. Without fencing, a delayed old agent could submit a late result.

Status: fixed.

Each delivery receives a cryptographically random lease token. Results must present the current token and a non-expired lease. Completed commands clear the token.

### 4. Production cookie configuration needed stronger invariants

A production deployment must not silently operate with an insecure session cookie.

Status: fixed.

Production configuration now requires SESSION_SECRET, BOOTSTRAP_TOKEN and COOKIE_SECURE=true.

## High-severity risks reviewed

### Tenant isolation

Every browser-side server operation resolves an organization membership before reading or mutating the server. Server ownership is checked against that organization. Agent authentication is separately bound to the server ID and hashed node token.

Status: acceptable for the current model.

Future requirement: centralize authorization policies once organization roles become more complex.

### Command execution

The API accepts a finite command vocabulary. The agent maps command types to local handlers and service names are allowlisted.

Status: acceptable.

Never add an arbitrary shell command payload to this protocol.

### Credential storage

User passwords use Argon2. Node credentials are high-entropy random values and only SHA-256 hashes are persisted.

Status: acceptable.

Future requirement: consider mTLS or short-lived node credentials for larger fleets.

### Database contention

Agent queue acquisition uses SELECT ... FOR UPDATE SKIP LOCKED. Cursor pagination avoids OFFSET scans. Composite indexes match server, command and audit query orderings.

Status: acceptable for the MVP and early fleet stages.

### API statelessness

API replicas keep no authoritative fleet state in process memory. PostgreSQL is the source of truth.

Status: acceptable.

## Medium-severity findings / intentional deferrals

### Distributed rate limiting

The application does not implement shared Redis rate limiting yet.

Mitigation: put login, bootstrap, agent and general API limits at the TLS/WAF edge.

Next scale stage: Redis-backed distributed rate limits.

### High-volume telemetry

Heartbeat metrics are intentionally bounded JSON state, not a time-series database.

Next scale stage: dedicated metrics ingestion into Prometheus-compatible storage or a managed time-series system.

### Long-running jobs

The command model is suitable for short node operations. Large backups, certificate issuance and other long-running workflows should eventually become durable asynchronous jobs with progress state.

### Session revocation

Sessions are signed and time-limited but not represented as individual server-side session rows.

Next scale stage: centralized session store or session-version invalidation if immediate revocation becomes a product requirement.

### Audit retention

Audit events are indexed but not yet partitioned.

Next scale stage: time partitioning and retention policies once event volume justifies it.

## Performance review

Current hot paths are:

1. authenticated request + membership lookup
2. server cursor pagination
3. command acquisition
4. heartbeat update
5. command result update

All five have bounded payloads and indexed persistence paths.

The API deliberately does not add Redis before there is a measured need. This keeps consistency simple while API replicas remain horizontally scalable.

## Deployment review

Production must:

1. Apply additive database migrations before deploying code that depends on them.
2. Inject secrets through the deployment environment or secret manager.
3. Terminate TLS before the API.
4. Restrict API network access to the edge where appropriate.
5. Run at least two API replicas for high availability.
6. Monitor /healthz and /readyz separately.
7. Back up PostgreSQL.
8. Centralize API, agent and database logs.
9. Keep the node agent outbound-only.

## Final review verdict

The architecture is suitable as a production MVP and provides a clean scaling path to a multi-node SaaS control plane.

It is not yet a hyperscale system, and the design deliberately avoids pretending otherwise. Redis, a dedicated message layer, telemetry storage, partitioned audit data, mTLS and distributed job workers are the next-stage components rather than mandatory dependencies for the current release.
