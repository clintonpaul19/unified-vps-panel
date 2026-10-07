import base64
import math
import re
import secrets
import time
import uuid
from urllib.parse import quote
from .config import SSH_PORTS,XRAY_TAGS
from .db import conn,log_event
from .hysteria import _hysteria_usage,kick_hysteria
from .ssh import add_ssh,del_ssh,set_ssh_enabled
from .system import public_host
from .xray import add_xray,del_xray,ensure_xray_client

def make_uri(row):
    host=public_host(); u=row['username']; s=row['secret']; p=row['protocol']
    if p in XRAY_TAGS:
        out={}
        for port in (80,443):
            tls = port == 443
            if p=='VLESS':
                params = f'type=ws&security={"tls" if tls else "none"}&path=%2Fvless'
                if tls:
                    params += f'&sni={quote(host,safe="")}'
                out[str(port)]=f'vless://{quote(s,safe="")}@{host}:{port}?{params}#{quote(u)}'
            elif p=='VMess':
                obj={'v':'2','ps':u,'add':host,'port':str(port),'id':s,'aid':'0','scy':'auto','net':'ws','type':'none','host':host,'path':'/vmess','tls':'tls' if tls else 'none'}
                if tls:
                    obj['sni']=host
                out[str(port)]='vmess://'+base64.b64encode(json.dumps(obj,separators=(',',':')).encode()).decode()
            else:
                out[str(port)]=f'trojan://{quote(s,safe="")}@{host}:{port}?security=tls&sni={quote(host,safe="")}&type=tcp#{quote(u)}'
        return out
    if p=='Hysteria': return {'53':f'hysteria2://{quote(s,safe="")}@{host}:53/?sni={quote(host,safe="")}#{quote(u)}'}
    if p=='SSH':
        ws_path=os.environ.get('SSH_WS_PATH','ssh').strip('/')
        return {
            'WebSocket': f'ws://{host}:80/{quote(ws_path,safe="")}',
            'WebSocket8080': f'ws://{host}:8080/{quote(ws_path,safe="")}',
            'WebSocket8880': f'ws://{host}:8880/{quote(ws_path,safe="")}',
            'WebSocketTLS': f'wss://{host}:443/{quote(ws_path,safe="")}',
            'WebSocketTLS8443': f'wss://{host}:8443/{quote(ws_path,safe="")}',
            'Host': host,
            'Path': '/'+ws_path
        }
    return {}

def record(row):
    d=dict(row); d['uris']=make_uri(row); d['host']=public_host()
    d['port']='80/443' if row['protocol'] in XRAY_TAGS else (','.join(map(str,SSH_PORTS)) if row['protocol']=='SSH' else {'Hysteria':53}.get(row['protocol']))
    return d

def create_user(d):
    p=d.get('protocol'); u=str(d.get('username',''))
    try: quota_gb=float(d.get('quota_gb',0) or 0)
    except (TypeError,ValueError): raise ValueError('quota must be a number')
    if not math.isfinite(quota_gb) or quota_gb < 0: raise ValueError('quota must be a finite non-negative number')
    q=int(quota_gb*(1024**3))
    if q > 9223372036854775807: raise ValueError('quota is too large')
    try: days=int(d.get('days',0) or 0)
    except (TypeError,ValueError): raise ValueError('days must be a whole number')
    if days < 0 or days > 36500: raise ValueError('duration must be between 0 and 36500 days')
    if p not in XRAY_TAGS and p not in ('Hysteria','SSH'): raise ValueError('invalid protocol')
    # SSH quota accounting is not currently supported, but accept the field
    # from CLI clients for compatibility and keep the stored quota at zero.
    if p=='SSH':
        q=0
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{2,31}',u): raise ValueError('invalid username')
    secret=str(d.get('secret') or (str(uuid.uuid4()) if p in ('VLESS','VMess') else secrets.token_urlsafe(18)))
    if p=='SSH' and not secret: raise ValueError('SSH password cannot be empty')
    if len(secret)>256 or '\n' in secret or '\r' in secret or '\x00' in secret: raise ValueError('secret/password contains invalid characters or is too long')
    if p in ('VLESS','VMess'):
        try:
            secret=str(uuid.UUID(secret))
        except ValueError:
            raise ValueError('VLESS/VMess ID must be a valid UUID')
    exp=int(time.time())+days*86400 if days else 0
    c=conn()
    ssh_created=False
    xray_created=False
    try:
        if c.execute('select 1 from users where username=?',(u,)).fetchone(): raise ValueError('username already exists')
        raw_baseline=0
        if p in XRAY_TAGS:
            stats=_xray_usage()
            if isinstance(stats,dict): raw_baseline=int(stats.get(u,0))
        elif p=='Hysteria':
            stats=_hysteria_usage()
            if isinstance(stats,dict): raw_baseline=int(stats.get(u,0))
        if p=='SSH':
            add_ssh(u,secret,days)
            ssh_created=True
        elif p!='Hysteria':
            add_xray(p,u,secret)
            xray_created=True
        today=time.strftime('%Y-%m-%d')
        c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at,raw_bytes,daily_used_bytes,usage_day) values(?,?,?,?,?,?,?,?,?)',
                  (u,p,secret,q,exp,int(time.time()),raw_baseline,0,today))
        c.commit()
        row=c.execute('select * from users where username=?',(u,)).fetchone()
        log_event('account_created',p,u)
        return record(row)
    except Exception:
        c.rollback()
        if ssh_created:
            del_ssh(u)
        if xray_created:
            try: del_xray(p,u)
            except Exception: pass
        raise
    finally: c.close()

def apply_user_action(uid, action, days=0, event_name=None):
    c=conn()
    row=c.execute('select * from users where id=?',(int(uid),)).fetchone()
    if not row:
        c.close()
        raise KeyError('not found')
    try:
        now=int(time.time())
        action=str(action).lower()
        if action=='delete':
            if row['protocol']=='SSH': del_ssh(row['username'])
            elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
            else: del_xray(row['protocol'],row['username'])
            c.execute('delete from users where id=?',(row['id'],))
            c.commit()
        elif action in ('enable','disable'):
            enable=action=='enable'
            if enable and row['expiry'] and row['expiry']<=now:
                raise ValueError('account is expired; renew it before enabling')
            if row['protocol'] in XRAY_TAGS:
                if enable: ensure_xray_client(row['protocol'],row['username'],row['secret'])
                else: del_xray(row['protocol'],row['username'])
            elif row['protocol']=='Hysteria':
                if not enable: kick_hysteria(row['username'])
            elif row['protocol']=='SSH':
                set_ssh_enabled(row['username'],enable,row['expiry'])
            c.execute('update users set enabled=? where id=?',(1 if enable else 0,row['id']))
            c.commit()
        elif action=='renew':
            days=int(days)
            if days <= 0 or days > 36500:
                raise ValueError('renewal duration must be between 1 and 36500 days')
            exp=now+days*86400
            baseline=int(row['raw_bytes'] or 0)
            if row['protocol'] in XRAY_TAGS:
                stats=_xray_usage()
                if isinstance(stats,dict): baseline=int(stats.get(row['username'],baseline))
                ensure_xray_client(row['protocol'],row['username'],row['secret'])
            elif row['protocol']=='Hysteria':
                stats=_hysteria_usage()
                if isinstance(stats,dict): baseline=int(stats.get(row['username'],baseline))
            elif row['protocol']=='SSH':
                set_ssh_enabled(row['username'],True,exp)
            c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',
                      (exp,baseline,time.strftime('%Y-%m-%d'),row['id']))
            c.commit()
        else:
            raise ValueError('unsupported action')
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
    log_event(event_name or ('account_deleted' if action=='delete' else 'account_'+action), row['protocol'], row['username'])
    return row
