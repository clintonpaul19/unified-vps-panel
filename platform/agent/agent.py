#!/usr/bin/env python3
"""Minimal Unified VPS node agent.

The agent never accepts arbitrary shell text. It pulls typed command names from the
control plane and executes only handlers defined in COMMAND_HANDLERS.
"""

import json, os, platform, socket, subprocess, time
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

BASE=os.environ["UVPS_CONTROL_PLANE_URL"].rstrip("/")
SERVER_ID=os.environ["UVPS_SERVER_ID"]
TOKEN=os.environ["UVPS_NODE_TOKEN"]
INTERVAL=float(os.environ.get("UVPS_HEARTBEAT_INTERVAL","15"))

SERVICE_ALLOWLIST={
    "ssh","nginx","haproxy","xray","hysteria-server",
    "unified-vps-panel","unified-vps-wstunnel-ssh","unified-vps-ws-payload-ssh",
}

def request(path, method="GET", payload=None):
    body=None if payload is None else json.dumps(payload).encode()
    req=Request(f"{BASE}{path}",data=body,method=method,headers={
        "Authorization":f"Bearer {TOKEN}",
        "Content-Type":"application/json",
        "User-Agent":"unified-vps-agent/0.1",
    })
    with urlopen(req,timeout=8) as r:
        raw=r.read().decode()
        return json.loads(raw) if raw else {}

def heartbeat():
    payload={
        "agent_version":"0.1.0",
        "hostname":socket.gethostname(),
        "status":"online",
        "metrics":{
            "os":platform.platform(),
            "python":platform.python_version(),
            "loadavg":os.getloadavg(),
        },
    }
    return request(f"/v1/servers/{SERVER_ID}/heartbeat","POST",payload)

def run_service_restart(payload):
    unit=str(payload.get("service",""))
    if unit not in SERVICE_ALLOWLIST:
        raise ValueError("service is not allowlisted")
    p=subprocess.run(["systemctl","restart",unit],capture_output=True,text=True,timeout=30)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or "restart failed")[-1000:])
    return {"service":unit,"ok":True}

def run_health_report(_payload):
    return {
        "hostname":socket.gethostname(),
        "platform":platform.platform(),
        "loadavg":os.getloadavg(),
        "uptime_seconds":time.monotonic(),
    }

COMMAND_HANDLERS={
    "service.restart":run_service_restart,
    "health.report":run_health_report,
}

def report(command, status, result=None, error=None):
    payload={"status":status}
    if result is not None: payload["result"]=result
    if error is not None: payload["error"]=error
    return request(f"/v1/servers/{SERVER_ID}/commands/{command['id']}/result","POST",payload)

def main():
    while True:
        try:
            heartbeat()
            while True:
                cmd=request(f"/v1/servers/{SERVER_ID}/commands/next")
                if not cmd:
                    break
                handler=COMMAND_HANDLERS.get(cmd.get("command_type"))
                if not handler:
                    report(cmd,"failed",error="unsupported command type")
                    continue
                report(cmd,"running")
                try:
                    result=handler(cmd.get("payload") or {})
                    report(cmd,"succeeded",result=result)
                except Exception as exc:
                    report(cmd,"failed",error=str(exc)[:2000])
        except (HTTPError,URLError,TimeoutError,OSError,ValueError) as exc:
            print(f"agent loop error: {exc}",flush=True)
        time.sleep(INTERVAL)

if __name__=="__main__":
    main()