# Unified VPS Platform — Production Architecture

The normative production design for the current control-plane implementation is documented in docs/PRODUCTION_ARCHITECTURE.md. This file remains the higher-level product architecture; the new document describes the concrete API, schema, pagination, container and caching boundaries.

## Product boundary

Unified VPS is split into two planes:

- **Control plane**: multi-tenant SaaS/API that stores users, organizations, servers, desired state, commands and audit history.
- **Node plane**: a lightweight agent running on each VPS. It executes approved changes locally and reports health/telemetry outbound to the control plane.

The existing single-VPS panel remains a node-local management surface. It is not treated as the global control plane.

## Logical architecture

```
                    ┌───────────────────────────┐
                    │        Web Console        │
                    │ Next.js/React in production│
                    └─────────────┬─────────────┘
                                  │ HTTPS
                    ┌─────────────▼─────────────┐
                    │       API Gateway         │
                    │ TLS / WAF / rate limits   │
                    └─────────────┬─────────────┘
                                  │
             ┌────────────────────▼────────────────────┐
             │             Control Plane               │
             │  Auth • Servers • Commands • Audit API │
             └───────┬──────────────┬─────────────────┘
                     │              │
             ┌───────▼──────┐ ┌────▼──────────────┐
             │ PostgreSQL   │ │ Redis / Queue      │
             │ source truth │ │ jobs + rate limits │
             └──────────────┘ └────┬───────────────┘
                                   │
                              ┌────▼─────┐
                              │ Workers  │
                              │ command  │
                              │ delivery │
                              └────┬─────┘
                                   │ outbound mTLS
                    ┌──────────────▼──────────────┐
                    │        VPS Node Agent       │
                    │ apply desired state locally │
                    └──────────────┬──────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ SSH / Xray / Hysteria /  │
                     │ HAProxy / systemd / nftables│
                     └───────────────────────────┘
```

## Scaling model

The API is stateless. Any request may hit any API instance. PostgreSQL is the transactional source of truth; Redis is an acceleration layer, not authoritative state. Commands are durable records and become asynchronous jobs so a slow or offline VPS never blocks an API request.

Horizontal scaling is:

1. Add API replicas behind the gateway.
2. Scale workers independently from API replicas.
3. Partition high-volume telemetry from transactional tables when necessary.
4. Add PostgreSQL read replicas for dashboard queries.
5. Move metrics/events to a time-series or streaming system once volume justifies it.
6. Keep the node agent outbound-only so VPS nodes do not require inbound control-plane ports.

## Reliability

Every mutating operation has an idempotency key. Commands have states: queued, sent, running, succeeded, failed, expired, cancelled. The desired-state model makes retries safe.

The node agent acknowledges a command with its command ID and a result payload. The control plane records the result in an append-only audit/event stream.

## Security

The control plane is HTTPS-only behind a trusted edge. User passwords are Argon2id hashes. Session cookies are HttpOnly, Secure and SameSite=Lax/Strict as appropriate. Node credentials are stored only as hashes. Node-to-control-plane traffic uses short-lived credentials or mTLS in the production deployment.

The node agent runs with the least Linux privileges possible and delegates narrowly scoped privileged actions to a root-owned helper. The existing local panel is intentionally kept separate from the global authentication domain.

## MVP implementation in this repository

The first vertical slice added under `platform/` is deliberately small:

- FastAPI control-plane API.
- PostgreSQL persistence.
- Organization/user/membership model.
- Cookie session authentication.
- Server registration with one-time node token display.
- Agent heartbeat endpoint.
- Durable command records.
- Audit events.
- Minimal dashboard UI.
- Docker Compose for local deployment.

Redis, mTLS provisioning and a Go node agent are kept as explicit seams rather than adding operational complexity before the core contract is stable.

## Non-goals for MVP

Do not move proxy configuration logic into the SaaS control plane. Do not let the web process execute arbitrary shell commands. Do not store node private keys or user proxy secrets in browser storage.
