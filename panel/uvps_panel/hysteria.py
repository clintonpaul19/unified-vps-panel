import json
from urllib.request import Request,urlopen
from .config import HY2_STATS_SECRET

def _hysteria_request(path,method='GET',payload=None):
    if not HY2_STATS_SECRET: return None
    try:
        data=json.dumps(payload).encode() if payload is not None else None
        headers={'Authorization':HY2_STATS_SECRET}
        if data is not None: headers['Content-Type']='application/json'
        req=Request(f'http://127.0.0.1:9999{path}',data=data,headers=headers,method=method)
        with urlopen(req,timeout=5) as r: return json.loads(r.read())
    except Exception:
        return None

def kick_hysteria(username):
    return _hysteria_request('/kick','POST',[str(username)]) is not None

def _hysteria_online():
    data=_hysteria_request('/online')
    if not isinstance(data,dict): return {}
    return {str(k):int(v or 0) for k,v in data.items()}

def _hysteria_usage():
    data=_hysteria_request('/traffic')
    if data is None: return None
    if not isinstance(data,dict): return {}
    return {str(k): int(v.get('tx',0))+int(v.get('rx',0)) for k,v in data.items() if isinstance(v,dict)}
