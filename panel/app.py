#!/usr/bin/env python3
import base64,hmac,html,json,os,secrets,sqlite3,subprocess,time,re
from urllib.parse import quote
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

BASE='/etc/unified-vps'
DB=f'{BASE}/panel.db'
CFG='/usr/local/etc/xray/config.json'
PORT=int(os.environ.get('PANEL_PORT','6080'))
DOMAIN=os.environ.get('SERVER_DOMAIN','')
ADMIN=os.environ.get('ADMIN_USER','spiderman')
PASSWORD=os.environ.get('ADMIN_PASSWORD','spiderman')
PUBLIC_IP_CACHE=None
XRAY_TAGS={'VLESS':['vless80','vless443'],'VMess':['vmess80','vmess443'],'Trojan':['trojan80','trojan443']}
SSH_PORTS=[80,443,143,8080,8443]

def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('''create table if not exists users(
        id integer primary key, username text unique, protocol text, secret text,
        quota_bytes integer default 0, used_bytes integer default 0,
        expiry integer default 0, enabled integer default 1, created_at integer)''')
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
    tmp=CFG+'.new'
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
    if p=='SSH': return {str(port):f'ssh://{quote(u,safe="")}:{quote(s,safe="")}@{host}:{port}' for port in SSH_PORTS}
    return {}

def record(row):
    d=dict(row); d['uris']=make_uri(row); d['host']=public_host()
    d['port']='80/443' if row['protocol'] in XRAY_TAGS else (','.join(map(str,SSH_PORTS)) if row['protocol']=='SSH' else {'Hysteria':53}.get(row['protocol']))
    return d

def create_user(d):
    p=d.get('protocol'); u=str(d.get('username','')); q=int(d.get('quota_bytes',0) or 0); days=int(d.get('days',0) or 0)
    if p not in XRAY_TAGS and p not in ('Hysteria','SSH'): raise ValueError('invalid protocol')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',u): raise ValueError('invalid username')
    secret=d.get('secret') or secrets.token_urlsafe(18)
    exp=int(time.time())+days*86400 if days else 0
    c=conn()
    try:
        if c.execute('select 1 from users where username=?',(u,)).fetchone(): raise ValueError('username already exists')
        if p=='SSH': add_ssh(u,secret,days)
        elif p!='Hysteria': add_xray(p,u,secret)
        c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at) values(?,?,?,?,?,?)',(u,p,secret,q,exp,int(time.time())))
        c.commit()
        row=c.execute('select * from users where username=?',(u,)).fetchone()
        return record(row)
    except Exception:
        c.rollback()
        if p=='SSH': subprocess.run(['userdel','-r',u],capture_output=True)
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
                p=subprocess.run(['speedtest','--accept-license','--accept-gdpr'],capture_output=True,text=True,timeout=180)
                return send(self,{'ok':p.returncode==0,'output':(p.stdout or p.stderr).strip()},200 if p.returncode==0 else 500)
            except Exception as e: return send(self,{'ok':False,'output':str(e)},500)
        if self.path=='/':
            c=conn(); rows=[record(x) for x in c.execute('select * from users order by id desc')]; c.close()
            trs=''
            for x in rows:
                safeuri=html.escape(x['uri'],quote=True)
                trs+=f'<tr><td>{html.escape(x["username"])}</td><td>{x["protocol"]}</td><td>{x["port"]}</td><td>{html.escape(x["secret"])}</td><td>{x["used_bytes"]}</td><td>{x["quota_bytes"] or "Unlimited"}</td><td>{"Yes" if x["enabled"] else "No"}</td><td><textarea id="u{x["id"]}" readonly>{safeuri}</textarea><button onclick="copyUri({x["id"]})">Copy URI</button></td></tr>'
            b=f'''<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Unified VPS Panel</title>
<style>body{{font-family:system-ui;background:#111;color:#eee;padding:20px}}input,select,button,textarea{{padding:8px;margin:4px;background:#222;color:#eee;border:1px solid #555}}textarea{{width:360px;height:45px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #444;padding:8px;text-align:left}}button{{cursor:pointer}}</style></head>
<body><h1>Unified VPS Panel</h1><p>Panel: http://{html.escape(public_ip())}:{PORT}</p>
<h2>Create account</h2><form id="f"><input name="username" placeholder="Username" required><select name="protocol"><option>Hysteria</option><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option></select><input name="days" type="number" value="0" min="0" placeholder="Days"><input name="quota_bytes" type="number" value="0" min="0" placeholder="Quota bytes"><button>Create</button></form>
<p><button onclick="runSpeedtest()">Run Ookla Speedtest</button></p><pre id="speed"></pre>
<h2>Accounts</h2><table><tr><th>User</th><th>Protocol</th><th>Port</th><th>Password / UUID</th><th>Used</th><th>Quota</th><th>Enabled</th><th>Copy URI</th></tr>{trs}</table>
<script>
async function copyUri(id){let e=document.getElementById('u'+id); try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(e.value);}else{e.focus();e.select();document.execCommand('copy');} alert('URI copied');}catch(_){e.focus();e.select();alert('URI selected — copy it manually.');}}
document.getElementById('f').onsubmit=async(e)=>{{e.preventDefault();let o=Object.fromEntries(new FormData(e.target));o.days=+o.days;o.quota_bytes=+o.quota_bytes;let r=await fetch('/api/users',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(o)}});let j=await r.json();alert(j.error||('Created: '+j.uri));if(r.ok) location.reload();}};
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
    conn().close(); ThreadingHTTPServer(('127.0.0.1',PORT),H).serve_forever()
