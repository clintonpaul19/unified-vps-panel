# Node-panel architecture

The node-local panel preserves the existing HTTP contract and legacy `/opt/unified-vps/panel.py` entrypoint, but the implementation is now separated into explicit layers.

## Folder structure

    panel/
    ├── __init__.py
    ├── app.py                    # compatibility launcher only
    └── uvps_panel/
        ├── __init__.py           # package marker
        ├── config.py             # runtime configuration and shared constants
        ├── db.py                 # SQLite initialization, connections, event persistence
        ├── cache.py              # bounded single-flight in-process cache
        ├── auth.py               # first-run setup, sessions, Basic Auth compatibility
        ├── http_utils.py         # request-body parsing and HTTP response primitives
        ├── xray.py               # Xray configuration lifecycle and usage API
        ├── ssh.py                # Linux SSH account lifecycle
        ├── hysteria.py           # Hysteria 2 management/statistics API
        ├── system.py             # OS/network/service/certificate/security telemetry
        ├── accounts.py            # account use-cases and connection URI generation
        ├── telemetry.py          # background usage synchronization and expiry enforcement
        ├── views.py              # setup/login/dashboard presentation
        ├── http.py               # HTTP transport and route orchestration
        └── main.py               # process bootstrap and bounded server

The control plane remains isolated under `platform/`:

    platform/
    ├── api/app/      # FastAPI application, persistence, models, schemas, security
    ├── agent/        # outbound node agent
    ├── db/           # PostgreSQL schema and deployable indexes
    └── web/          # control-plane UI

## Dependency direction

    app.py
      -> main
         -> http
            -> views
            -> accounts
            -> telemetry/services
            -> http_utils
         -> infrastructure modules
              db / auth / xray / ssh / hysteria / system

Business operations do not construct HTTP responses directly. The HTTP layer translates requests to service calls; infrastructure modules own their respective external systems.

## Compatibility contract

No public node-panel route was intentionally renamed or removed. The systemd unit still launches `/opt/unified-vps/panel.py`, but that file is now only a compatibility wrapper. The installer and updater deploy the package beside it.

The existing first-run administrator setup, login/session behavior, SSH, VLESS, VMess, Trojan, Hysteria 2, WebSocket transports, account expiry, usage tracking, backup/restore, certificates, watchdog, Fail2Ban, Speedtest and CLI compatibility are preserved.

## Operational boundary

The node panel is still a privileged local control surface. It owns Linux/Xray/Hysteria side effects and SQLite metadata. The scalable control plane does not execute arbitrary shell text and communicates to nodes through typed commands and an outbound agent.

The node panel should not be treated as the horizontally scaled SaaS tier. For fleet-scale workloads, the control-plane API, workers, PostgreSQL and agent delivery path are the scaling boundary.

## Remaining architectural work

The next refactor stage should extract long-running maintenance operations into a local job executor, introduce cursor pagination for large account datasets, and eventually move high-volume telemetry and command delivery to dedicated queue/time-series infrastructure.
