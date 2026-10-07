# Unified VPS Control Plane MVP

This directory contains the first scalable control-plane vertical slice for Unified VPS.

## Run locally

From the repository root:

```bash
export SESSION_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export BOOTSTRAP_ADMIN_PASSWORD='change-this-before-starting'
docker compose -f platform/docker-compose.yml up --build
```

The console is exposed on port 8000.

The node token returned by `POST /v1/servers` is shown only once. Store it in the node agent configuration.

## Production topology

Run the API behind a TLS edge, use managed PostgreSQL, add Redis for rate limiting/job queues, and run API/worker replicas independently. Do not expose PostgreSQL publicly.

The MVP intentionally avoids an arbitrary shell execution API. Commands are typed records; the future agent maps each type to a fixed implementation.
