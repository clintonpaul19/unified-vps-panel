# Control Plane API

All browser-facing routes use an HttpOnly signed session cookie. Agent routes use a bearer node token.

## Health
`GET /healthz`
`GET /readyz`

## Authentication
`POST /v1/auth/bootstrap` — creates the initial organization/admin only when the database is empty.
`POST /v1/auth/login`
`POST /v1/auth/logout`
`GET /v1/me`

When `BOOTSTRAP_TOKEN` is configured, bootstrap also requires `X-Bootstrap-Token`.

## Organizations
`GET /v1/organizations`

Users with one organization may omit organization context. Multi-organization users must send `X-Organization-ID`.

## Servers
`GET /v1/servers`
`GET /v1/servers/{server_id}`
`POST /v1/servers`
`POST /v1/servers/{server_id}/tokens` — rotates the node token; the new value is returned once.

## Agent
`POST /v1/servers/{server_id}/heartbeat`
`GET /v1/servers/{server_id}/commands/next`
`POST /v1/servers/{server_id}/commands/{command_id}/result` — agent result must include the current lease_token

## Commands
`POST /v1/servers/{server_id}/commands`
`GET /v1/servers/{server_id}/commands`
`POST /v1/servers/{server_id}/commands/{command_id}/cancel`

Commands are typed data. The API never accepts an arbitrary executable shell string.

Command creation supports an idempotency key. Agent delivery uses a bounded lease, a per-delivery lease token, and bounded attempts so crashed or stale nodes cannot permanently strand or later mutate reclaimed work.

## Audit
`GET /v1/events`

## Production deployment

Put the API behind an HTTPS edge. Use managed PostgreSQL. Keep PostgreSQL private. Set `ENVIRONMENT=production`, provide a high-entropy `SESSION_SECRET`, enable Secure cookies, and keep automatic schema creation disabled. Add a migration job before application rollout.