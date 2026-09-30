#!/usr/bin/env python3
import base64,hashlib,hmac,html,json,math,os,secrets,sqlite3,subprocess,time,re,threading,uuid
from urllib.request import Request,urlopen
from urllib.parse import quote
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

BASE='/etc/unified-vps'
DB=f'{BASE}/panel.db'
CFG='/usr/local/etc/xray/config.json'
PORT=int(os.environ.get('PANEL_PORT','6080'))
DOMAIN=os.environ.get('SERVER_DOMAIN','')
ADMIN=os.environ.get('ADMIN_USER','').strip()
PASSWORD=os.environ.get('ADMIN_PASSWORD','')
PANEL_ENV=f'{BASE}/panel.env'
SESSION_COOKIE='uvps_session'
SESSION_TTL=12*60*60
SETUP_LOCK=threading.Lock()
CERT_LOCK=threading.Lock()
LOGIN_LOCK=threading.Lock()
LOGIN_ATTEMPTS={}
SPEEDTEST_LOCK=threading.Lock()
HY2_STATS_SECRET=os.environ.get('HY2_STATS_SECRET','')
PUBLIC_IP_CACHE=None
XRAY_TAGS={'VLESS':['vless443'],'VMess':['vmess443'],'Trojan':['trojan443']}
SSH_PORTS=[80,443,143,8080,8443,8880]
XRAY_LOCK=threading.RLock()
MAX_REQUEST_BODY=64*1024

def conn():
    os.makedirs(BASE,exist_ok=True)
    c=sqlite3.connect(DB,timeout=10); c.row_factory=sqlite3.Row
    c.execute('''create table if not exists users(
        id integer primary key, username text unique, protocol text, secret text,
        quota_bytes integer default 0, used_bytes integer default 0,
        expiry integer default 0, enabled integer default 1, created_at integer, raw_bytes integer default 0,
        daily_used_bytes integer default 0, usage_day text default '')''')
    for stmt in (
        'alter table users add column raw_bytes integer default 0',
        'alter table users add column daily_used_bytes integer default 0',
        "alter table users add column usage_day text default ''",
    ):
        try: c.execute(stmt)
        except sqlite3.OperationalError: pass
    c.execute('''create table if not exists server_usage(
        id integer primary key check(id=1),
        raw_rx integer default 0, raw_tx integer default 0,
        all_time_bytes integer default 0, daily_bytes integer default 0,
        usage_day text default ''
    )''')
    c.execute('''create table if not exists events(
        id integer primary key, created_at integer, action text, username text default '', details text default ''
    )''')
    c.execute('''create table if not exists usage_daily(
        day text primary key, bytes integer default 0
    )''')
    c.execute('insert or ignore into server_usage(id,raw_rx,raw_tx,all_time_bytes,daily_bytes,usage_day) values(1,0,0,0,0,?)',
              (time.strftime('%Y-%m-%d'),))
    c.commit(); return c

def admin_configured():
    return bool(ADMIN and PASSWORD)

def _session_cookie(username):
    issued=str(int(time.time()))
    payload=f'{username}|{issued}'
    secret=f'{ADMIN}\0{PASSWORD}'.encode()
    sig=hmac.new(secret,payload.encode(),hashlib.sha256).hexdigest()
    return f'{payload}|{sig}'

def _session_valid(cookie):
    if not admin_configured() or not cookie: return False
    try:
        username,issued,sig=cookie.split('|',2)
        issued=int(issued)
        if username!=ADMIN or issued<0 or time.time()-issued>SESSION_TTL: return False
        payload=f'{username}|{issued}'
        expected=hmac.new(f'{ADMIN}\0{PASSWORD}'.encode(),payload.encode(),hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig,expected)
    except Exception:
        return False

def auth(h,remote_addr=''):
    if not admin_configured(): return False
    v=h.get('Authorization','')
    if v.startswith('Basic ') and remote_addr in ('127.0.0.1','localhost'):
        try:
            u,p=base64.b64decode(v[6:]).decode().split(':',1)
            if hmac.compare_digest(u,ADMIN) and hmac.compare_digest(p,PASSWORD): return True
        except Exception:
            pass
    cookie_header=h.get('Cookie','')
    for item in cookie_header.split(';'):
        item=item.strip()
        if item.startswith(SESSION_COOKIE+'=') and _session_valid(item.split('=',1)[1]): return True
    return False

def _save_admin_credentials(username,password):
    global ADMIN,PASSWORD
    os.makedirs(BASE,exist_ok=True)
    try:
        with open(PANEL_ENV,encoding='utf-8') as f: lines=f.read().splitlines()
    except OSError:
        lines=[]
    def env_quote(value):
        return json.dumps(value,ensure_ascii=False).replace(chr(36),chr(92)+chr(36)).replace(chr(96),chr(92)+chr(96))
    out=[]; user_done=False; pass_done=False
    for line in lines:
        if line.startswith('ADMIN_USER='):
            out.append('ADMIN_USER='+env_quote(username)); user_done=True
        elif line.startswith('ADMIN_PASSWORD='):
            out.append('ADMIN_PASSWORD='+env_quote(password)); pass_done=True
        else:
            out.append(line)
    if not user_done: out.append('ADMIN_USER='+env_quote(username))
    if not pass_done: out.append('ADMIN_PASSWORD='+env_quote(password))
    tmp=PANEL_ENV+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: f.write('\n'.join(out)+'\n')
    os.chmod(tmp,0o600)
    os.replace(tmp,PANEL_ENV)
    ADMIN=username
    PASSWORD=password

def retire_legacy_admin():
    global ADMIN,PASSWORD
    if ADMIN.lower()!='spiderman':
        return False
    try:
        _save_admin_credentials('','')
    except Exception:
        ADMIN=''; PASSWORD=''
    return True
def send_html(r,html_body,status=200,headers=None):
    b=html_body.encode()
    r.send_response(status)
    r.send_header('Content-Type','text/html; charset=utf-8')
    r.send_header('Cache-Control','no-store')
    if headers:
        for k,v in headers.items(): r.send_header(k,v)
    r.send_header('Content-Length',str(len(b)))
    r.end_headers()
    r.wfile.write(b)

def _setup_page(r):
    page='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unified VPS — Initial Setup</title>
<style>:root{--bg:#06110b;--panel:#0b1811;--line:#173524;--text:#ecfff2;--muted:#87a995;--accent:#42f58d;--danger:#ff6b78}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(800px 500px at 50% -10%,rgba(66,245,141,.11),transparent 60%),var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}.card{width:min(460px,100%);padding:28px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg,rgba(14,33,22,.96),rgba(8,20,13,.96));box-shadow:0 30px 90px rgba(0,0,0,.45)}.logo{font-weight:900;letter-spacing:.04em;color:var(--accent);font-size:13px}.title{font-size:26px;margin:8px 0 4px}.sub{color:var(--muted);margin:0 0 22px}label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}.field{margin-bottom:14px}input{width:100%;padding:12px 13px;border-radius:10px;border:1px solid var(--line);background:#06100a;color:var(--text);outline:none}button{width:100%;margin-top:8px;border:0;border-radius:11px;padding:12px 14px;background:linear-gradient(135deg,var(--accent),#1dbb68);color:#03200f;font-weight:800;cursor:pointer}.msg{min-height:20px;margin-top:12px;color:var(--danger);font-size:12px}.note{margin-top:18px;color:var(--muted);font-size:11px}</style></head><body><main class="card"><div class="logo">UNIFIED VPS</div><div class="title">Initial setup</div><p class="sub">Create the administrator account for this VPS panel.</p><form id="setup"><div class="field"><label>Enter username</label><input name="username" maxlength="32" autocomplete="username" required></div><div class="field"><label>Enter password</label><input name="password" type="password" minlength="8" maxlength="128" autocomplete="new-password" required></div><div class="field"><label>Reenter password</label><input name="confirm" type="password" minlength="8" maxlength="128" autocomplete="new-password" required></div><button type="submit">Save and login</button><div id="msg" class="msg"></div></form><div class="note">Your administrator credentials are stored locally on this VPS.</div></main><script>const f=document.getElementById("setup"),m=document.getElementById("msg");f.onsubmit=async e=>{e.preventDefault();m.textContent="";const d=Object.fromEntries(new FormData(f).entries());if(d.password!==d.confirm){m.textContent="Passwords do not match.";return}try{const r=await fetch("/setup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}),j=await r.json();if(!r.ok){m.textContent=j.error||"Setup failed.";return}location.href="/"}catch(_){m.textContent="Setup request failed."}};</script></body></html>'''
    return send_html(r,page)

def send(r,obj,status=200):
    b=json.dumps(obj).encode(); r.send_response(status)
    r.send_header('Content-Type','application/json'); r.send_header('Content-Length',str(len(b)))
    r.end_headers(); r.wfile.write(b)