#!/usr/bin/env python3
import base64,hmac,html,json,os,secrets,sqlite3,subprocess,time,re,threading
from urllib.request import Request,urlopen
from urllib.parse import quote
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

BASE='/etc/unified-vps'
DB=f'{BASE}/panel.db'
CFG='/usr/local/etc/xray/config.json'
PORT=int(os.environ.get('PANEL_PORT','6080'))
DOMAIN=os.environ.get('SERVER_DOMAIN','')
ADMIN=os.environ.get('ADMIN_USER','spiderman')
PASSWORD=os.environ.get('ADMIN_PASSWORD','spiderman')
HY2_STATS_SECRET=os.environ.get('HY2_STATS_SECRET','')
PUBLIC_IP_CACHE=None
XRAY_TAGS={'VLESS':['vless443'],'VMess':['vmess443'],'Trojan':['trojan443']}
SSH_PORTS=[80,443,143,8080,8443]

def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('''create table if not exists users(
        id integer primary key, username text unique, protocol text, secret text,
        quota_bytes integer default 0, used_bytes integer default 0,
        expiry integer default 0, enabled integer default 1, created_at integer, raw_bytes integer default 0)''')
    try: c.execute('alter table users add column raw_bytes integer default 0')
    except sqlite3.OperationalError: pass
    c.commit(); return c

def auth(h):
    v=h.get('Authorization','')
    if not v.startswith('Basic '): return False
    try: u,p=base64.b64decode(v[6:]).decode().split(':',1)
    except Exception: return False
    return hmac.compare_digest(u,ADMIN) and hmac.compare_digest(p,PASSWORD)

def send(r,obj,status=200):
    b=json.dumps(obj).encode(); r.send_response(status)
    r.send_header('Content-Type','application/json'); r.send_header('Content-Length',str(len(b)))
    r.end_headers(); r.wfile.write(b)

def body(r): return json.loads(r.rfile.read(int(r.headers.get('Content-Length','0')) or 2))

def public_host():
    return DOMAIN or public_ip()

def public_ip():
    global PUBLIC_IP_CACHE
    if PUBLIC_IP_CACHE: return PUBLIC_IP_CACHE
    try:
        PUBLIC_IP_CACHE=subprocess.check_output(['curl','-4fsS','--max-time','3','https://api.ipify.org'],text=True).strip()
    except Exception:
        PUBLIC_IP_CACHE='SERVER_IP'
    return PUBLIC_IP_CACHE

def load_xray():
    with open(CFG) as f: return json.load(f)

def save_xray(d):
    tmp=CFG+'.tmp.json'
    with open(tmp,'w') as f: json.dump(d,f,indent=2)
    test=subprocess.run(['xray','-test','-config',tmp],capture_output=True,text=True)
    if test.returncode:
        try: os.unlink(tmp)
        except OSError: pass
        raise RuntimeError('Xray configuration test failed: '+(test.stderr or test.stdout).strip())
    os.replace(tmp,CFG)
    rr=subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
    if rr.returncode: raise RuntimeError('Xray restart failed: '+(rr.stderr or rr.stdout).strip())

def add_xray(protocol,u,secret):
    d=load_xray()
    for tag in XRAY_TAGS[protocol]:
        ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
        if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
        clients=ib.setdefault('settings',{}).setdefault('clients',[])
        if any(c.get('email')==u for c in clients): raise RuntimeError('Username already exists in Xray')
        c={'email':u,'level':0}
        c['id' if protocol in ('VMess','VLESS') else 'password']=secret
        clients.append(c)
    save_xray(d)

def del_xray(protocol,u):
    d=load_xray(); changed=False
    for tag in XRAY_TAGS[protocol]:
        ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
        if ib:
            old=len(ib['settings'].get('clients',[]))
            ib['settings']['clients']=[x for x in ib['settings'].get('clients',[]) if x.get('email')!=u]
            changed |= old != len(ib['settings']['clients'])
    if changed: save_xray(d)

def add_ssh(u,password,days):
    if subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError('Linux SSH username already exists')
    subprocess.run(['useradd','-m','-s','/bin/bash',u],check=True)
    p=subprocess.run(['chpasswd'],input=f'{u}:{password}\n',text=True,capture_output=True)
    if p.returncode:
        subprocess.run(['userdel','-r',u],capture_output=True)
        raise RuntimeError('Failed to set SSH password')
    if days:
        subprocess.run(['chage','-E',str((int(time.time())+days*86400)//86400+1),u],check=False)

def del_ssh(u):
    subprocess.run(['userdel','-r',u],capture_output=True)


def _xray_usage():
    try:
        p=subprocess.run(['xray','api','statsquery','--server=127.0.0.1:10085'],capture_output=True,text=True,timeout=10)
        if p.returncode != 0: return {}
        data=json.loads(p.stdout)
        out={}
        for item in data.get('stat',[]):
            name=item.get('name','')
            parts=name.split('>>>')
            if len(parts)==4 and parts[0]=='user' and parts[2]=='traffic' and parts[3] in ('uplink','downlink'):
                out.setdefault(parts[1],0)
                out[parts[1]] += int(item.get('value',0))
        return out
    except Exception:
        return {}

def _hysteria_usage():
    if not HY2_STATS_SECRET: return {}
    try:
        req=Request('http://127.0.0.1:9999/traffic',headers={'Authorization':HY2_STATS_SECRET})
        with urlopen(req,timeout=5) as r: data=json.loads(r.read())
        return {str(k): int(v.get('tx',0))+int(v.get('rx',0)) for k,v in data.items()}
    except Exception:
        return {}

def sync_usage():
    while True:
        try:
            xusage=_xray_usage()
            husage=_hysteria_usage()
            c=conn()
            rows=c.execute('select * from users').fetchall()
            now=int(time.time())
            disable=[]
            for row in rows:
                if row['protocol'] in XRAY_TAGS:
                    raw=xusage.get(row['username'],0)
                elif row['protocol']=='Hysteria':
                    raw=husage.get(row['username'],0)
                else:
                    raw=0
                prev=int(row['raw_bytes'] or 0)
                delta=max(raw-prev,0)
                used=int(row['used_bytes'] or 0)+delta
                expired=bool(row['expiry'] and row['expiry']<=now)
                quota_hit=bool(row['quota_bytes'] and used>=row['quota_bytes'])
                if row['enabled'] and (expired or quota_hit):
                    disable.append(row)
                c.execute('update users set used_bytes=?,raw_bytes=? where id=?',(used,raw,row['id']))
            c.commit(); c.close()

            xrows=[r for r in disable if r['protocol'] in XRAY_TAGS]
            if xrows:
                d=load_xray(); changed=False
                for row in xrows:
                    for tag in XRAY_TAGS[row['protocol']]:
                        ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
                        if ib:
                            before=len(ib.get('settings',{}).get('clients',[]))
                            ib['settings']['clients']=[u for u in ib['settings'].get('clients',[]) if u.get('email')!=row['username']]
                            changed |= before != len(ib['settings']['clients'])
                if changed: save_xray(d)

            c=conn()
            for row in disable:
                if row['protocol']=='SSH':
                    subprocess.run(['usermod','-L',row['username']],capture_output=True)
                c.execute('update users set enabled=0 where id=?',(row['id'],))
            c.commit(); c.close()
        except Exception:
            pass
        time.sleep(15)

def make_uri(row):
    host=public_host(); u=row['username']; s=row['secret']; p=row['protocol']
    if p in XRAY_TAGS:
        out={}
        for port in (80,443):
            if p=='VLESS':
                out[str(port)]=f'vless://{quote(s,safe="")}@{host}:{port}?type=ws&security=tls&sni={quote(host,safe="")}&path=%2Fvless#{quote(u)}'
            elif p=='VMess':
                obj={'v':'2','ps':u,'add':host,'port':str(port),'id':s,'aid':'0','scy':'auto','net':'ws','type':'none','host':host,'path':'/vmess','tls':'tls','sni':host}
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
    p=d.get('protocol'); u=str(d.get('username','')); quota_gb=float(d.get('quota_gb',0) or 0); q=int(quota_gb*(1024**3)); days=int(d.get('days',0) or 0)
    if quota_gb < 0: raise ValueError('quota cannot be negative')
    if p not in XRAY_TAGS and p not in ('Hysteria','SSH'): raise ValueError('invalid protocol')
    if p=='SSH' and quota_gb: raise ValueError('Per-user quotas are supported for Xray and Hysteria only')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',u): raise ValueError('invalid username')
    secret=d.get('secret') or secrets.token_urlsafe(18)
    exp=int(time.time())+days*86400 if days else 0
    c=conn()
    ssh_created=False
    xray_created=False
    try:
        if c.execute('select 1 from users where username=?',(u,)).fetchone(): raise ValueError('username already exists')
        if p=='SSH':
            add_ssh(u,secret,days)
            ssh_created=True
        elif p!='Hysteria':
            add_xray(p,u,secret)
            xray_created=True
        c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at) values(?,?,?,?,?,?)',(u,p,secret,q,exp,int(time.time())))
        c.commit()
        row=c.execute('select * from users where username=?',(u,)).fetchone()
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

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=='/health': return send(self,{'ok':True})
        if not auth(self.headers):
            self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return
        if self.path=='/api/users':
            c=conn(); rows=[record(x) for x in c.execute('select * from users order by id desc')]; c.close(); return send(self,rows)
        if self.path=='/api/speedtest':
            try:
                env=os.environ.copy()
                env.update({'HOME':'/root','USER':'root','LOGNAME':'root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'})
                p=subprocess.run(['speedtest','--accept-license','--accept-gdpr'],capture_output=True,text=True,timeout=180,env=env)
                output=(p.stdout or p.stderr).strip()
                if p.returncode != 0 and not output:
                    output=f'Speedtest exited with code {p.returncode}'
                return send(self,{'ok':p.returncode==0,'output':output},200 if p.returncode==0 else 500)
            except Exception as e: return send(self,{'ok':False,'output':str(e)},500)
        if self.path=='/':
            c=conn(); rows=[record(x) for x in c.execute('select * from users order by id desc')]; c.close()
            trs=''
            for x in rows:
                xid=x['id']; username=x['username']; protocol=x['protocol']; port_value=x['port']; secret=x['secret']
                used=x['used_bytes']; quota=x['quota_bytes']; enabled=x['enabled']
                if protocol in XRAY_TAGS:
                    a=html.escape(x['uris'].get('80',''),quote=True)
                    b2=html.escape(x['uris'].get('443',''),quote=True)
                    connection=f'<textarea id="u{xid}a" readonly>{a}</textarea><button onclick="copyUri(\'u{xid}a\')">Copy 80</button><br><textarea id="u{xid}b" readonly>{b2}</textarea><button onclick="copyUri(\'u{xid}b\')">Copy 443</button>'
                elif protocol=='SSH':
                    host=html.escape(x['host'],quote=True)
                    ws_path=html.escape(x['uris'].get('Path','/ssh'),quote=True)
                    ws80=html.escape(x['uris'].get('WebSocket',''),quote=True)
                    ws8080=html.escape(x['uris'].get('WebSocket8080',''),quote=True)
                    ws8880=html.escape(x['uris'].get('WebSocket8880',''),quote=True)
                    wss443=html.escape(x['uris'].get('WebSocketTLS',''),quote=True)
                    wss8443=html.escape(x['uris'].get('WebSocketTLS8443',''),quote=True)
                    connection=f'Host: {host}<br>WS Path: {ws_path}<br>WS 80: <textarea id="u{xid}ws80" readonly>{ws80}</textarea><button onclick="copyUri(\'u{xid}ws80\')">Copy</button><br>WS 8080: <textarea id="u{xid}ws8080" readonly>{ws8080}</textarea><button onclick="copyUri(\'u{xid}ws8080\')">Copy</button><br>WS 8880: <textarea id="u{xid}ws8880" readonly>{ws8880}</textarea><button onclick="copyUri(\'u{xid}ws8880\')">Copy</button><br>WSS 443: <textarea id="u{xid}wss443" readonly>{wss443}</textarea><button onclick="copyUri(\'u{xid}wss443\')">Copy</button><br>WSS 8443: <textarea id="u{xid}wss8443" readonly>{wss8443}</textarea><button onclick="copyUri(\'u{xid}wss8443\')">Copy</button><br>Payload: <code>GET {ws_path} HTTP/1.1 | Host: {host} | Upgrade: websocket | Connection: Upgrade</code>'
                else:
                    uri=next(iter(x['uris'].values()),'')
                    connection=f'<textarea id="u{xid}" readonly>{html.escape(uri,quote=True)}</textarea><button onclick="copyUri(\'u{xid}\')">Copy URI</button>'
                enabled_text='Yes' if enabled else 'No'
                used_text='Unlimited' if False else f'{used/(1024**3):.2f} GB'
                quota_text='Unlimited' if not quota else f'{quota/(1024**3):.2f} GB'
                trs+=f'<tr><td>{html.escape(username)}</td><td>{protocol}</td><td>{port_value}</td><td>{html.escape(secret)}</td><td>{used_text}</td><td>{quota_text}</td><td>{enabled_text}</td><td>{connection}</td></tr>'
            b=f'''<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Unified VPS Panel</title>
<style>body{{font-family:system-ui;background:#111;color:#eee;padding:20px}}input,select,button,textarea{{padding:8px;margin:4px;background:#222;color:#eee;border:1px solid #555}}textarea{{width:360px;height:45px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #444;padding:8px;text-align:left}}button{{cursor:pointer}}</style></head>
<body><h1>Unified VPS Panel</h1><p>Panel: https://{html.escape(public_host())}/</p>
<h2>Create account</h2><form id="f"><div><label>Username<br><input name="username" placeholder="Username" required></label></div><div><label>Protocol<br><select id="protocol" name="protocol"><option>Hysteria</option><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option></select></label></div><div id="passwordRow" style="display:none"><label>SSH Password<br><input id="sshPassword" name="secret" type="password" placeholder="Password" autocomplete="new-password"></label></div><div><label>Duration (days)<br><input name="days" type="number" value="0" min="0" placeholder="0 = unlimited"></label></div><div id="quotaRow"><label>Quota (GB)<br><input id="quotaGb" name="quota_gb" type="number" value="0" min="0" step="0.1" placeholder="0 = unlimited"></label></div><button>Create</button></form>
<p><button onclick="runSpeedtest()">Run Ookla Speedtest</button></p><pre id="speed"></pre>
<h2>Accounts</h2><table><tr><th>User</th><th>Protocol</th><th>Port</th><th>Password / UUID</th><th>Used</th><th>Quota</th><th>Enabled</th><th>Connection</th></tr>{trs}</table>
<script>
async function copyUri(id){{let e=document.getElementById('u'+id); try{{if(navigator.clipboard&&window.isSecureContext){{await navigator.clipboard.writeText(e.value);}}else{{e.focus();e.select();document.execCommand('copy');}} alert('URI copied');}}catch(_){{e.focus();e.select();alert('URI selected — copy it manually.');}}}}
const protocolSelect=document.getElementById('protocol'),passwordRow=document.getElementById('passwordRow'),sshPassword=document.getElementById('sshPassword');
const quotaRow=document.getElementById('quotaRow'),quotaGb=document.getElementById('quotaGb');
function updateProtocolFields(){{let ssh=protocolSelect.value==='SSH';passwordRow.style.display=ssh?'block':'none';sshPassword.required=ssh;if(!ssh)sshPassword.value='';quotaRow.style.opacity=ssh?'0.5':'1';quotaGb.disabled=ssh;if(ssh)quotaGb.value='0';}}
protocolSelect.onchange=updateProtocolFields;updateProtocolFields();
document.getElementById('f').onsubmit=async(e)=>{{e.preventDefault();let o=Object.fromEntries(new FormData(e.target));o.days=+o.days;o.quota_gb=+o.quota_gb;let r=await fetch('/api/users',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(o)}});let j=await r.json();alert(j.error||'Created. Connection details are shown in the account list.');if(r.ok) location.reload();}};
async function runSpeedtest(){{document.getElementById('speed').textContent='Running Ookla Speedtest...';let r=await fetch('/api/speedtest');let j=await r.json();document.getElementById('speed').textContent=j.output||j.error||'No result';}}
</script></body></html>'''.encode()
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path=='/hysteria-auth':
            try: d=body(self)
            except Exception: return send(self,{'ok':False},400)
            secret=str(d.get('auth','')); c=conn()
            r=c.execute('select username,expiry,enabled from users where protocol="Hysteria" and secret=?',(secret,)).fetchone(); c.close()
            if not r or not r['enabled'] or (r['expiry'] and r['expiry']<=int(time.time())): return send(self,{'ok':False})
            return send(self,{'ok':True,'id':r['username']})
        if not auth(self.headers):
            self.send_response(401); self.end_headers(); return
        try: d=body(self)
        except Exception: return send(self,{'error':'invalid JSON'},400)
        if self.path=='/api/users':
            try: return send(self,create_user(d))
            except Exception as e: return send(self,{'error':str(e)},500)
        if self.path=='/api/users/action':
            c=conn(); row=c.execute('select * from users where id=?',(int(d.get('id',0)),)).fetchone()
            if not row: c.close(); return send(self,{'error':'not found'},404)
            action=str(d.get('action','')).lower()
            try:
                if action=='renew':
                    days=int(d.get('days',0) or 0)
                    if days <= 0: raise ValueError('renewal days must be greater than 0')
                    exp=int(time.time())+days*86400
                    c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=0 where id=?',(exp,row['id']))
                    if row['protocol'] in XRAY_TAGS:
                        try: del_xray(row['protocol'],row['username'])
                        except Exception: pass
                        add_xray(row['protocol'],row['username'],row['secret'])
                    elif row['protocol']=='SSH':
                        subprocess.run(['usermod','-U',row['username']],capture_output=True)
                    c.commit()
                    return send(self,{'ok':True,'action':'renew','id':row['id']})
                if action in ('enable','disable'):
                    enable=action=='enable'
                    if enable:
                        if row['protocol'] in XRAY_TAGS:
                            dcfg=load_xray()
                            for tag in XRAY_TAGS[row['protocol']]:
                                ib=next((i for i in dcfg.get('inbounds',[]) if i.get('tag')==tag),None)
                                if ib:
                                    clients=ib.setdefault('settings',{}).setdefault('clients',[])
                                    if not any(x.get('email')==row['username'] for x in clients):
                                        client={'email':row['username'],'level':0}
                                        client['id' if row['protocol'] in ('VMess','VLESS') else 'password']=row['secret']
                                        clients.append(client)
                            save_xray(dcfg)
                        elif row['protocol']=='SSH':
                            subprocess.run(['usermod','-U',row['username']],capture_output=True)
                    else:
                        if row['protocol'] in XRAY_TAGS:
                            del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='SSH':
                            subprocess.run(['usermod','-L',row['username']],capture_output=True)
                    c.execute('update users set enabled=? where id=?',(1 if enable else 0,row['id']))
                    c.commit()
                    return send(self,{'ok':True,'action':action,'id':row['id']})
                return send(self,{'error':'unsupported action'},400)
            except Exception as e:
                c.rollback(); return send(self,{'error':str(e)},500)
            finally: c.close()

        if self.path=='/api/users/delete':
            c=conn(); row=c.execute('select * from users where id=?',(int(d.get('id',0)),)).fetchone()
            if not row: c.close(); return send(self,{'error':'not found'},404)
            try:
                if row['protocol']=='SSH': del_ssh(row['username'])
                elif row['protocol']!='Hysteria': del_xray(row['protocol'],row['username'])
                c.execute('delete from users where id=?',(row['id'],)); c.commit(); return send(self,{'ok':True})
            except Exception as e: c.rollback(); return send(self,{'error':str(e)},500)
            finally: c.close()
        return send(self,{'error':'not found'},404)

if __name__=='__main__':
    conn().close()
    threading.Thread(target=sync_usage,daemon=True).start()
    ThreadingHTTPServer(('127.0.0.1',PORT),H).serve_forever()
