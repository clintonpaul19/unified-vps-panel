# Control Plane API

Base path: `/v1`

Authentication for human operators uses the session cookie. Agent endpoints use a bearer node token.

## Health

`GET /healthz`

Returns service and database readiness.

## Auth

`POST /v1/auth/bootstrap`
Creates the first organization/admin from bootstrap environment variables. Disabled after the first successful bootstrap.

`POST /v1/auth/login`
JSON body:

```json
{"email":"admin@example.com","password":"..."}
```

`POST /v1/auth/logout`

`GET /v1/me`

## Servers

`GET /v1/servers`

`POST /v1/servers`
Creates a node record. The response contains the node token exactly once; only its hash is persisted.

`GET /v1/servers/{server_id}`

`POST /v1/servers/{server_id}/heartbeat`
Agent-authenticated. Accepts status, version, hostname, IP addresses and resource metadata.

`POST /v1/servers/{server_id}/commands`
Human-authenticated. Creates a durable command.

`GET /v1/servers/{server_id}/commands`

## Audit

`GET /v1/events?limit=100`

## Command lifecycle

```
queued -> sent -> running -> succeeded
                     \-> failed
queued -> expired
queued -> cancelled
```

Commands are data, not executable shell fragments. The agent maps a typed command name to a fixed local implementation.
