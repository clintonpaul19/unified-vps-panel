# Unified VPS — scalable production architecture

## 1. System architecture

The production system is deliberately split into a stateless control plane and a privileged node plane.

    Internet
       |
       v
    TLS edge / WAF / rate limiting
       |
       v
    API replicas (FastAPI)
       |
       +--------------------+
       |                    |
       v                    v
    PostgreSQL          Redis (optional)
    source of truth     cache / queues / rate limits
       |
       v
    durable commands
       |
       v
    outbound node agent
       |
       v
    VPS-local privileged operations
    SSH / Xray / Hysteria / HAProxy / systemd

The browser talks only to the control-plane API. A VPS node never exposes an inbound management port for the control plane; the node agent initiates outbound HTTPS connections.

The existing node-local panel remains the operational fallback for one VPS. It is not the multi-tenant database or fleet control surface.

## 2. Component structure

    platform/
    ├── api/
    │   ├── app/
    │   │   ├── config.py       # typed runtime configuration
    │   │   ├── db.py           # async SQLAlchemy engine/session
    │   │   ├── models.py       # PostgreSQL persistence model
    │   │   ├── schemas.py      # validated API contracts
    │   │   ├── security.py     # Argon2, sessions, node-token hashing
    │   │   ├── pagination.py   # signed opaque cursors
    │   │   ├── middleware.py   # request id, headers, timing logs
    │   │   └── main.py         # HTTP orchestration
    │   ├── requirements.txt    # reproducible runtime dependencies
    │   └── Dockerfile          # non-root production image
    ├── agent/
    │   └── agent.py            # outbound-only node worker
    ├── db/
    │   ├── schema.sql          # new-database bootstrap schema
    │   ├── PERFORMANCE_INDEXES.sql
    │   └── MIGRATIONS.md       # migration policy
    └── web/
        └── index.html          # minimal control-plane console

The application is intentionally small. Domain complexity grows by adding service/repository modules rather than turning the HTTP entrypoint into a cross-cutting monolith.

## 3. Data flow

### User authentication

1. Browser sends credentials over HTTPS to the edge.
2. API validates the account with Argon2id.
3. API returns an HttpOnly, Secure session cookie in production.
4. Every authenticated request resolves the user and explicit organization context.

### Server registration

1. Operator creates a server record.
2. API commits server metadata and a SHA-256 hash of a generated node token in one transaction.
3. The raw node token is returned once and never stored.
4. The node agent uses the token over outbound HTTPS.

### Heartbeat

1. Agent sends health and bounded metrics.
2. API updates the server heartbeat state.
3. Read APIs derive stale nodes as offline after the configured heartbeat timeout.
4. Dashboard reads remain bounded by page size.

### Command execution

1. Operator submits a typed command and optional idempotency key.
2. API commits a durable command record plus an audit event.
3. Agent polls its queue.
4. PostgreSQL row locking with SKIP LOCKED assigns one command to one poller.
5. The command receives a time-bounded lease.
6. Agent executes only a local allowlisted handler.
7. Agent reports running/succeeded/failed.
8. The API stores the final result or bounded error text.

A crashed agent does not lose a command permanently. After the lease expires, another poller can claim it until the maximum attempt count is reached. A command that exceeds the retry budget is marked expired.

## 4. API design

Base path: /v1

| Resource | Method | Purpose |
| --- | --- | --- |
| /auth/bootstrap | POST | One-time control-plane bootstrap |
| /auth/login | POST | Create signed session |
| /auth/logout | POST | Clear browser session cookie |
| /me | GET | Current user |
| /organizations | GET | Membership-visible organizations |
| /servers | GET | Cursor-paginated server list |
| /servers/{id} | GET | Server detail |
| /servers | POST | Register server and issue one-time token |
| /servers/{id}/tokens | POST | Rotate node credentials |
| /servers/{id}/heartbeat | POST | Agent health update |
| /servers/{id}/commands/next | GET | Agent lease acquisition |
| /servers/{id}/commands | POST | Queue typed command |
| /servers/{id}/commands | GET | Cursor-paginated command history |
| /servers/{id}/commands/{id}/result | POST | Agent result |
| /servers/{id}/commands/{id}/cancel | POST | Cancel queued command |
| /events | GET | Cursor-paginated audit history |

Pagination is backward-compatible with the current list response shape. Clients send limit and cursor; the API returns the same JSON array and supplies X-Next-Cursor when another page exists.

Every request receives X-Request-ID. Clients can provide a safe correlation id or allow the API to generate one.

## 5. Database schema

PostgreSQL is the transactional source of truth.

### organizations

Tenant boundary. Unique slug.

### users

Login identity, Argon2id password hash, activation state and last login.

### memberships

Many-to-many user/organization relationship with owner/admin/operator/viewer authorization.

### servers

Tenant-scoped VPS inventory, network identity, agent version, status, heartbeat time and a bounded metrics JSON document.

### server_tokens

Only SHA-256 hashes of node credentials are stored. Tokens are revocable and rotatable without changing the server identity.

### commands

Durable typed work records with organization and server ownership, command type, bounded JSON payload, idempotency key, queue state, lease deadline, attempt count, execution timestamps and bounded result/error.

### audit_events

Append-only tenant-scoped security and operational events.

The main hot paths have composite indexes that match the cursor ordering and agent queue filters, preventing offset scans as the data set grows.

## 6. Caching strategy

Do not cache authoritative mutations.

For the first production slice, PostgreSQL remains the source of truth and dashboard reads are bounded and indexed. This avoids the consistency problems of introducing a distributed cache before it is necessary.

When read volume grows:

1. Add Redis as a shared cache, never as the authoritative database.
2. Cache only read-heavy, low-volatility material such as organization membership summaries, server summary projections and short-lived dashboard aggregates.
3. Use short TTLs such as 5–30 seconds and invalidate on successful mutations where practical.
4. Keep login, authorization and security decisions backed by the database or a dedicated session store.
5. Cache failures only very briefly to avoid masking recovery.
6. Use per-key single-flight in API workers to prevent cache stampedes.

Node-local caching is separate: the existing node panel uses bounded, single-flight in-process caching for expensive host telemetry. That cache does not cross VPS boundaries.

## 7. Scaling model

### 0–100 nodes

- 2 API replicas
- managed PostgreSQL
- direct agent polling
- no Redis required

### 100–2,000 nodes

- API replicas scale independently
- increase PostgreSQL pool carefully rather than blindly
- introduce Redis for rate limiting and short-lived dashboard caching
- move command delivery to a queue or long-poll mechanism
- centralize metrics/logs

### 2,000+ nodes

- dedicated command workers
- Redis Streams, NATS, SQS or equivalent delivery layer
- PostgreSQL read replicas for dashboards
- partition high-volume telemetry/audit data
- object storage for backups and large artifacts
- workload isolation by organization

The key invariant is that API scale does not require node-local state to be migrated into the API process.

## 8. Production controls

The API container runs as a non-root user. Schema creation is disabled by default in production. Bootstrap credentials and the session secret come from deployment secrets, not source control.

The TLS edge should provide WAF and distributed rate limiting, especially for login, bootstrap and agent endpoints. The application itself remains stateless so multiple API replicas can run behind that edge.

## 9. Current implementation boundaries

Implemented in this slice:

- PostgreSQL-backed multi-tenant model
- one-time bootstrap serialization
- Argon2id user authentication
- hashed node tokens and rotation
- typed commands with idempotency
- lease/retry/expiry semantics
- cursor pagination without response-shape breakage
- stale-heartbeat status derivation
- request correlation and safe security headers
- bounded JSON payloads
- reproducible non-root container
- database indexes for the new hot paths
- outbound-only agent

Deliberately deferred:

- Redis
- distributed rate-limit state
- dedicated command workers
- mTLS provisioning
- high-volume telemetry storage
- organization billing/quotas
- local async job executor for long-running maintenance tasks

Those are scale-stage components, not prerequisites for a sound MVP.

## 10. Design rule

The control plane owns desired state, identity, authorization and durable work. The node agent owns privileged execution. Neither side is allowed to become an arbitrary remote shell.
