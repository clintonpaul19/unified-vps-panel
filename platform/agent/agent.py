#!/usr/bin/env python3
"""Minimal outbound-only Unified VPS node agent."""

import json
import os
import platform
import random
import socket
import subprocess
import time
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = os.environ["UVPS_CONTROL_PLANE_URL"].rstrip("/")
_parts = urlsplit(BASE)
if not _parts.netloc:
    raise RuntimeError("UVPS_CONTROL_PLANE_URL must include a hostname")
if _parts.scheme != "https" and os.environ.get("UVPS_ALLOW_INSECURE_HTTP", "").lower() != "true":
    raise RuntimeError("UVPS_CONTROL_PLANE_URL must use HTTPS")
SERVER_ID = os.environ["UVPS_SERVER_ID"]
TOKEN = os.environ["UVPS_NODE_TOKEN"]
INTERVAL = max(float(os.environ.get("UVPS_HEARTBEAT_INTERVAL", "30")), 5.0)
AGENT_VERSION = "0.3.0"
HOSTNAME = socket.gethostname()
PLATFORM = platform.platform()
PYTHON_VERSION = platform.python_version()
HTTP_USER_AGENT = "unified-vps-agent/" + AGENT_VERSION

SERVICE_ALLOWLIST = {
    "ssh",
    "nginx",
    "haproxy",
    "xray",
    "hysteria-server",
    "unified-vps-panel",
    "unified-vps-wstunnel-ssh",
    "unified-vps-ws-payload-ssh",
}


def request(path, method="GET", payload=None):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = Request(
        f"{BASE}{path}",
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": HTTP_USER_AGENT,
        },
    )
    with urlopen(req, timeout=8) as response:
        raw = response.read()
        return json.loads(raw.decode()) if raw else {}


def uptime_seconds():
    try:
        with open("/proc/uptime", encoding="utf-8") as fh:
            return float(fh.read().split()[0])
    except Exception:
        return 0.0


def heartbeat():
    try:
        loadavg = list(os.getloadavg())
    except (AttributeError, OSError):
        loadavg = [0.0, 0.0, 0.0]
    return request(
        f"/v1/servers/{SERVER_ID}/heartbeat",
        "POST",
        {
            "agent_version": AGENT_VERSION,
            "hostname": HOSTNAME,
            "status": "online",
            "metrics": {
                "os": PLATFORM,
                "python": PYTHON_VERSION,
                "loadavg": loadavg,
                "uptime_seconds": uptime_seconds(),
            },
        },
    )


def run_service_restart(payload):
    unit = str(payload.get("service", ""))
    if unit not in SERVICE_ALLOWLIST:
        raise ValueError("service is not allowlisted")
    process = subprocess.run(
        ["systemctl", "restart", unit],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if process.returncode:
        raise RuntimeError((process.stderr or process.stdout or "restart failed")[-1000:])
    return {"service": unit, "ok": True}


def run_health_report(_payload):
    try:
        loadavg = list(os.getloadavg())
    except (AttributeError, OSError):
        loadavg = [0.0, 0.0, 0.0]
    return {
        "hostname": HOSTNAME,
        "platform": PLATFORM,
        "loadavg": loadavg,
        "uptime_seconds": uptime_seconds(),
    }


COMMAND_HANDLERS = {
    "service.restart": run_service_restart,
    "health.report": run_health_report,
}


def report(command, status_value, result=None, error=None):
    lease_token = command.get("lease_token")
    if not lease_token:
        raise ValueError("command did not include a lease token")
    payload = {"lease_token": lease_token, "status": status_value}
    if result is not None:
        payload["result"] = result
    if error is not None:
        payload["error"] = error
    return request(
        f"/v1/servers/{SERVER_ID}/commands/{command['id']}/result",
        "POST",
        payload,
    )


def main():
    failures = 0
    while True:
        try:
            heartbeat()
            failures = 0
            while True:
                command = request(f"/v1/servers/{SERVER_ID}/commands/next")
                if not command:
                    break
                handler = COMMAND_HANDLERS.get(command.get("command_type"))
                if not handler:
                    report(command, "failed", error="unsupported command type")
                    continue
                report(command, "running")
                try:
                    result = handler(command.get("payload") or {})
                    report(command, "succeeded", result=result)
                except Exception as exc:
                    report(command, "failed", error=str(exc)[:2000])
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"agent loop error: {exc}", flush=True)
            failures = min(failures + 1, 6)
        delay = min(INTERVAL * (2 ** failures), 300.0) + random.uniform(
            0, min(5.0, INTERVAL / 3)
        )
        time.sleep(delay)


if __name__ == "__main__":
    main()
