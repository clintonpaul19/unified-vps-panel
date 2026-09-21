#!/usr/bin/env python3
import base64,hmac,html,json,os,secrets,sqlite3,subprocess,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
BASE='/etc/unified-vps'; DB=f'{BASE}/panel.db'; CFG='/usr/local/etc/xray/config.json'; PORT=int(os.environ.get('PANEL_PORT','2087'))
ADMIN=os.environ.get('ADMIN_USER','admin'); PASSWORD=os.environ.get('ADMIN_PASSWORD','')
def conn():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def auth(h):
 v=h.get('Authorization','')
 if not v.startswith('Basic '): return False
 try:u,p=base64.b64decode(v[6:]).decode().split(':',1)
 except Exception:return False
 return hmac.compare_digest(u,ADMIN) and hmac.compare_digest(p,PASSWORD)
def send(r,obj,status=200):
 b=json.dumps(obj).encode(); r.send_response(status); r.send_header('Content-Type','application/json'); r.send_header('Content-Length',str(len(b))); r.end_headers(); r.wfile.write(b)
def body(r): return json.loads(r.rfile.read(int(r.headers.get('Content-Length','0')) or 2))
def xray():
 try:return json.load(open(CFG))
 except Exception:return None
def save_xray(d):
 os.makedirs(os.path.dirname(CFG),exist_ok=True); tmp=CFG+'.new'; open(tmp,'w').write(json.dumps(d,indent=2)); os.replace(tmp,CFG); subprocess.run(['systemctl','restart','xray'],check=False)
def add_xray(protocol,u,secret):
 d=xray()
 if d is None: raise RuntimeError('Xray config missing')
 tag={'VMess':'vmess443','VLESS':'vless80','Trojan':'trojan443'}[protocol]
 ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
 if ib is None: raise RuntimeError(f'{protocol} inbound missing')
 c={'email':u,'level':0}; c['id' if protocol in ('VMess','VLESS') else 'password']=secret
 ib.setdefault('settings',{}).setdefault('clients',[]).append(c); save_xray(d)
def del_xray(protocol,u):
 d=xray(); tag={'VMess':'vmess443','VLESS':'vless80','Trojan':'trojan443'}[protocol]
 ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
 if ib: ib['settings']['clients']=[c for c in ib.get('settings',{}).get('clients',[]) if c.get('email')!=u]; save_xray(d)
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/health': return send(self,{'ok':True})
  if not auth(self.headers):
   self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return
  c=conn()
  if self.path=='/api/users':
   rows=[dict(x) for x in c.execute('select * from users order by id desc')]; c.close(); return send(self,rows)
  if self.path=='/':
   rows=c.execute('select username,protocol,used_bytes,quota_bytes,expiry,enabled from users order by id desc').fetchall(); c.close()
   trs=''.join(f'<tr><td>{html.escape(r[0])}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3] or "Unlimited"}</td><td>{"Yes" if r[5] else "No"}</td></tr>' for r in rows)
   b=f'<meta name="viewport" content="width=device-width"><body style="font-family:system-ui;background:#111;color:#eee;padding:24px"><h1>Unified VPS Panel</h1><p>SSH 22 · Hysteria UDP 53 · WS 80 · WSS 443 · VMess 10086 · VLESS 10087 · Trojan 10088 · BadVPN UDP 7100-7300</p><table border=1 cellpadding=8><tr><th>User</th><th>Protocol</th><th>Used</th><th>Quota</th><th>Enabled</th></tr>{trs}</table></body>'.encode()
   self.send_response(200); self.send_header('Content-Type','text/html'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
  c.close(); self.send_response(404); self.end_headers()
 def do_POST(self):
  if self.path=='/hysteria-auth':
   try:d=body(self)
   except Exception:return send(self,{'ok':False},400)
   secret=str(d.get('auth','')); c=conn(); r=c.execute('select username,expiry from users where protocol="Hysteria" and secret=? and enabled=1',(secret,)).fetchone(); c.close()
   if not r or (r['expiry'] and r['expiry']<=int(time.time())): return send(self,{'ok':False})
   return send(self,{'ok':True,'id':r['username']})
  if not auth(self.headers): return self.send_response(401)
  try:d=body(self)
  except Exception:return send(self,{'error':'invalid JSON'},400)
  c=conn()
  if self.path=='/api/users':
   p=d.get('protocol'); u=d.get('username',''); q=int(d.get('quota_bytes',0) or 0); days=int(d.get('days',0) or 0)
   if p not in ('Hysteria','VMess','VLESS','Trojan') or not u.replace('_','').replace('-','').replace('.','').isalnum(): return send(self,{'error':'invalid user/protocol'},400)
   secret=d.get('secret') or (secrets.token_urlsafe(18) if p in ('Hysteria','Trojan') else subprocess.check_output(['xray','uuid'],text=True).strip())
   exp=int(time.time())+days*86400 if days else 0
   try:
    if p!='Hysteria': add_xray(p,u,secret)
    c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at) values(?,?,?,?,?,?)',(u,p,secret,q,exp,int(time.time()))); c.commit()
    return send(self,{'ok':True,'username':u,'protocol':p,'secret':secret,'expiry':exp})
   except Exception as e:return send(self,{'error':str(e)},500)
  if self.path=='/api/users/delete':
   r=c.execute('select * from users where id=?',(int(d.get('id',0)),)).fetchone()
   if not r:return send(self,{'error':'not found'},404)
   try:
    if r['protocol']!='Hysteria':del_xray(r['protocol'],r['username'])
    c.execute('delete from users where id=?',(r['id'],)); c.commit(); return send(self,{'ok':True})
   except Exception as e:return send(self,{'error':str(e)},500)
  return send(self,{'error':'not found'},404)
if __name__=='__main__': conn().close(); ThreadingHTTPServer(('0.0.0.0',PORT),H).serve_forever()
