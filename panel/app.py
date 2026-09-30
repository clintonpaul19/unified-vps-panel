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
    return bool(ADMIN and PASSWORD) and not (ADMIN=='spiderman' and PASSWORD=='spiderman')

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

def auth(h):
    if not admin_configured(): return False
    v=h.get('Authorization','')
    if v.startswith('Basic '):
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
        return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('        else:
            out.append(line)
    if not user_done: out.append('ADMIN_USER='+env_quote(username))
    if not pass_done: out.append('ADMIN_PASSWORD='+env_quote(password))
    tmp=PANEL_ENV+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: f.write('\n'.join(out)+'\n')
    os.chmod(tmp,0o600)
    os.replace(tmp,PANEL_ENV)
    ADMIN=username
    PASSWORD=password

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

def body(r):
    try:
        length=int(r.headers.get('Content-Length','0') or 0)
    except (TypeError,ValueError):
        raise ValueError('invalid content length')
    if length<0 or length>MAX_REQUEST_BODY:
        raise ValueError('request body too large')
    raw=r.rfile.read(length)
    return json.loads(raw or b'{}')

def public_host():
    return DOMAIN or public_ip()

def public_ip():
    global PUBLIC_IP_CACHE
    if PUBLIC_IP_CACHE: return PUBLIC_IP_CACHE
    try:
        value=subprocess.check_output(['curl','-4fsS','--max-time','3','https://api.ipify.org'],text=True).strip()
        if value:
            PUBLIC_IP_CACHE=value
            return value
    except Exception:
        pass
    return 'SERVER_IP'

def load_xray():
    with open(CFG) as f: return json.load(f)

def save_xray(d):
    with XRAY_LOCK:
        tmp=CFG+'.tmp.json'
        rollback=CFG+'.rollback.tmp'
        try:
            with open(CFG,'rb') as f: previous=f.read()
        except OSError:
            previous=None
        with open(tmp,'w') as f: json.dump(d,f,indent=2)
        test=subprocess.run(['xray','-test','-config',tmp],capture_output=True,text=True)
        if test.returncode:
            try: os.unlink(tmp)
            except OSError: pass
            raise RuntimeError('Xray configuration test failed: '+(test.stderr or test.stdout).strip())
        os.replace(tmp,CFG)
        rr=subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
        if rr.returncode:
            if previous is not None:
                try:
                    with open(rollback,'wb') as f: f.write(previous)
                    os.replace(rollback,CFG)
                    subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
                except Exception:
                    pass
            raise RuntimeError('Xray restart failed: '+(rr.stderr or rr.stdout).strip())

def add_xray(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray()
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            if any(c.get('email')==u for c in clients): raise RuntimeError('Username already exists in Xray')
            client={'email':u,'level':0}
            client['id' if protocol in ('VMess','VLESS') else 'password']=secret
            clients.append(client)
        save_xray(d)

def ensure_xray_client(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        key='id' if protocol in ('VMess','VLESS') else 'password'
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            client=next((x for x in clients if x.get('email')==u),None)
            if client is None:
                clients.append({'email':u,'level':0,key:secret}); changed=True
            elif client.get(key)!=secret:
                client[key]=secret; changed=True
        if changed: save_xray(d)

def del_xray(protocol,u):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib:
                old=len(ib['settings'].get('clients',[]))
                ib['settings']['clients']=[x for x in ib['settings'].get('clients',[]) if x.get('email')!=u]
                changed |= old != len(ib['settings']['clients'])
        if changed: save_xray(d)

def sync_ssh_expiry(u,expiry):
    if expiry:
        exp_date=time.strftime('%Y-%m-%d',time.localtime(int(expiry)+86400))
        subprocess.run(['chage','-E',exp_date,u],check=False)
    else:
        subprocess.run(['chage','-E','-1',u],check=False)

def set_ssh_enabled(u,enabled,expiry=None):
    p=subprocess.run(['usermod','-U' if enabled else '-L',u],capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to change SSH account state')
    if enabled and expiry is not None:
        sync_ssh_expiry(u,expiry)
    elif not enabled:
        subprocess.run(['pkill','-TERM','-u',u],capture_output=True)

def add_ssh(u,password,days):
    if subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError('Linux SSH username already exists')
    subprocess.run(['useradd','-m','-s','/bin/bash',u],check=True)
    p=subprocess.run(['chpasswd'],input=f'{u}:{password}\n',text=True,capture_output=True)
    if p.returncode:
        subprocess.run(['userdel','-r',u],capture_output=True)
        raise RuntimeError('Failed to set SSH password')
    subprocess.run(['usermod','-U',u],capture_output=True,check=False)
    sync_ssh_expiry(u, int(time.time())+days*86400 if days else 0)

def del_ssh(u):
    if subprocess.run(['id',u],capture_output=True).returncode != 0:
        return
    subprocess.run(['pkill','-TERM','-u',u],capture_output=True)
    p=subprocess.run(['userdel','-r',u],capture_output=True,text=True)
    if p.returncode and subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to delete SSH account')

def _xray_usage():
    try:
        p=subprocess.run(['xray','api','statsquery','--server=127.0.0.1:10085'],capture_output=True,text=True,timeout=10)
        if p.returncode != 0: return None
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
        return None

def _hysteria_request(path, method='GET', payload=None):
    if not HY2_STATS_SECRET:
        return None
    try:
        data=None
        headers={'Authorization':HY2_STATS_SECRET}
        if payload is not None:
            data=json.dumps(payload).encode()
            headers['Content-Type']='application/json'
        req=Request(f'http://127.0.0.1:9999{path}',data=data,headers=headers,method=method)
        with urlopen(req,timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None

def kick_hysteria(username):
    return _hysteria_request('/kick','POST',[str(username)]) is not None

def _hysteria_usage():
    data=_hysteria_request('/traffic')
    if data is None: return None
    if not isinstance(data,dict): return {}
    return {str(k): int(v.get('tx',0))+int(v.get('rx',0)) for k,v in data.items() if isinstance(v,dict)}

def _primary_interface():
    try:
        out=subprocess.check_output(['ip','route','show','default'],text=True,timeout=3)
        parts=out.split()
        return parts[parts.index('dev')+1] if 'dev' in parts else ''
    except Exception:
        return ''

def _server_bytes():
    iface=_primary_interface()
    if not iface: return 0,0
    try:
        with open(f'/sys/class/net/{iface}/statistics/rx_bytes') as f: rx=int(f.read().strip())
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes') as f: tx=int(f.read().strip())
        return rx,tx
    except Exception:
        return 0,0

def _human_bytes(n):
    n=float(max(int(n or 0),0))
    units=('B','KB','MB','GB','TB','PB')
    for u in units:
        if n < 1024 or u==units[-1]:
            return f'{n:.2f} {u}'
        n/=1024
    return '0.00 B'

def log_event(action, details='', username=''):
    try:
        c=conn()
        c.execute('insert into events(created_at,action,username,details) values(?,?,?,?)',
                  (int(time.time()),str(action),str(username),str(details)))
        c.execute('delete from events where id not in (select id from events order by id desc limit 500)')
        c.commit(); c.close()
    except Exception:
        pass

def _network_rate():
    iface=_primary_interface()
    if not iface:
        return {'rx_bytes':0,'tx_bytes':0,'rx_bps':0,'tx_bps':0}
    try:
        with open(f'/sys/class/net/{iface}/statistics/rx_bytes') as f: rx=int(f.read())
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes') as f: tx=int(f.read())
        now=time.time()
        prev=getattr(_network_rate,'prev',None)
        _network_rate.prev=(now,rx,tx)
        if not prev:
            return {'rx_bytes':rx,'tx_bytes':tx,'rx_bps':0,'tx_bps':0}
        dt=max(now-prev[0],0.1)
        return {'rx_bytes':rx,'tx_bytes':tx,'rx_bps':max(rx-prev[1],0)/dt,'tx_bps':max(tx-prev[2],0)/dt}
    except Exception:
        return {'rx_bytes':0,'tx_bytes':0,'rx_bps':0,'tx_bps':0}

def _system_metrics():
    try:
        load=os.getloadavg()
    except Exception:
        load=(0,0,0)
    mem={}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k,v=line.split(':',1)
                mem[k]=int(v.strip().split()[0])*1024
    except Exception:
        pass
    total=mem.get('MemTotal',0); available=mem.get('MemAvailable',0)
    used=max(total-available,0)
    du=__import__('shutil').disk_usage('/')
    net=_network_rate()
    return {
        'timestamp':int(time.time()),
        'cpu_load':[round(float(x),2) for x in load],
        'cpu_count':os.cpu_count() or 1,
        'memory':{'total':total,'used':used,'available':available},
        'disk':{'total':du.total,'used':du.used,'free':du.free},
        'network':net,
        'uptime_seconds':int(time.time()-__import__('psutil').boot_time()) if __import__('importlib').util.find_spec('psutil') else 0
    }

def _active_sessions():
    out=[]
    try:
        p=subprocess.run(['ss','-Hntp','state','established'],capture_output=True,text=True,timeout=5)
        for line in p.stdout.splitlines():
            parts=line.split()
            if len(parts)<5: continue
            local=parts[2]; peer=parts[3]
            proc=''
            pid=None
            m=re.search(r'users:\(\("([^"]+)",pid=(\d+)',line)
            if m:
                proc=m.group(1); pid=int(m.group(2))
            user=''
            if pid:
                try: user=subprocess.check_output(['ps','-o','user=','-p',str(pid)],text=True).strip()
                except Exception: pass
            out.append({'local':local,'remote':peer,'process':proc,'pid':pid,'user':user})
            if len(out)>=100: break
    except Exception:
        pass
    return out

def _certificate_info():
    path='/etc/unified-vps/xray.crt'
    if not os.path.exists(path): return {'ok':False,'error':'Certificate not found'}
    try:
        p=subprocess.run(['openssl','x509','-in',path,'-noout','-subject','-issuer','-startdate','-enddate'],
                         capture_output=True,text=True,timeout=5)
        vals={}
        for line in p.stdout.splitlines():
            if '=' in line:
                k,v=line.split('=',1); vals[k.strip()]=v.strip()
        end=vals.get('notAfter','')
        epoch=0
        if end:
            epoch=int(time.mktime(time.strptime(end,'%b %d %H:%M:%S %Y %Z')))
        days=int((epoch-time.time())/86400) if epoch else -1
        return {'ok':p.returncode==0,'subject':vals.get('subject',''),'issuer':vals.get('issuer',''),
                'start':vals.get('notBefore',''),'expiry':end,'days_remaining':days}
    except Exception as e:
        return {'ok':False,'error':str(e)}

def _security_info():
    failed=0
    try:
        text=subprocess.check_output(['journalctl','-u','ssh','--since','24 hours ago','--no-pager'],text=True,stderr=subprocess.DEVNULL)
        failed=sum(1 for x in text.splitlines() if 'Failed password' in x or 'Invalid user' in x)
    except Exception: pass
    banned=0; f2b='inactive'
    try:
        f2b=service_state('fail2ban')
        text=subprocess.check_output(['fail2ban-client','status','sshd'],text=True,stderr=subprocess.DEVNULL)
        m=re.search(r'Currently banned:\s*(\d+)',text); banned=int(m.group(1)) if m else 0
    except Exception: pass
    try:
        fw=sum(1 for x in subprocess.check_output(['iptables','-S','INPUT'],text=True,stderr=subprocess.DEVNULL).splitlines() if x.strip())
    except Exception: fw=0
    try:
        ssh_cfg=subprocess.check_output(['sshd','-T'],text=True,stderr=subprocess.DEVNULL)
        auth_cfg={k:v for k,v in (line.split(None,1) for line in ssh_cfg.splitlines() if line.split(None,1)[0] in ('passwordauthentication','kbdinteractiveauthentication','usepam'))}
    except Exception: auth_cfg={}
    return {'fail2ban':f2b,'banned':banned,'failed_ssh_24h':failed,'firewall_rules':fw,'ssh_auth':auth_cfg}

def sync_usage():
    while True:
        try:
            xusage=_xray_usage()
            husage=_hysteria_usage()
            c=conn()
            rows=c.execute('select * from users').fetchall()
            now=int(time.time())
            today=time.strftime('%Y-%m-%d',time.localtime(now))
            disable=[]
            for row in rows:
                if row['protocol'] in XRAY_TAGS:
                    if xusage is None: continue
                    raw=xusage.get(row['username'],0)
                elif row['protocol']=='Hysteria':
                    if husage is None: continue
                    raw=husage.get(row['username'],0)
                else:
                    raw=0
                prev=int(row['raw_bytes'] or 0)
                delta=raw-prev if raw >= prev else raw
                used=int(row['used_bytes'] or 0)+delta
                daily=int(row['daily_used_bytes'] or 0)
                usage_day=row['usage_day'] or ''
                if usage_day != today:
                    daily=0
                daily += delta
                expired=bool(row['expiry'] and row['expiry']<=now)
                quota_hit=bool(row['quota_bytes'] and used>=row['quota_bytes'])
                if row['enabled'] and (expired or quota_hit):
                    disable.append(row)
                c.execute('update users set used_bytes=?,raw_bytes=?,daily_used_bytes=?,usage_day=? where id=?',
                          (used,raw,daily,today,row['id']))

            rx,tx=_server_bytes()
            srv=c.execute('select * from server_usage where id=1').fetchone()
            if srv:
                raw_rx=int(srv['raw_rx'] or 0); raw_tx=int(srv['raw_tx'] or 0)
                server_delta=(rx-raw_rx if rx >= raw_rx else rx)+(tx-raw_tx if tx >= raw_tx else tx)
                server_all=int(srv['all_time_bytes'] or 0)+server_delta
                server_daily=int(srv['daily_bytes'] or 0)
                if (srv['usage_day'] or '') != today:
                    server_daily=0
                server_daily += server_delta
                c.execute('update server_usage set raw_rx=?,raw_tx=?,all_time_bytes=?,daily_bytes=?,usage_day=? where id=1',
                          (rx,tx,server_all,server_daily,today))
                c.execute('insert into usage_daily(day,bytes) values(?,?) on conflict(day) do update set bytes=excluded.bytes',
                          (today,server_daily))
            c.commit(); c.close()

            xrows=[r for r in disable if r['protocol'] in XRAY_TAGS]
            if xrows:
                with XRAY_LOCK:
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
                log_event('account_auto_disabled','expired or quota reached',row['username'])
                if row['protocol']=='Hysteria':
                    kick_hysteria(row['username'])
                if row['protocol']=='SSH':
                    try: set_ssh_enabled(row['username'],False)
                    except Exception: pass
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
    except (TypeError,ValueError): raise ValueError('quota must be a finite non-negative number')
    if not math.isfinite(quota_gb) or quota_gb < 0: raise ValueError('quota must be a finite non-negative number')
    q=int(quota_gb*(1024**3))
    try: days=int(d.get('days',0) or 0)
    except (TypeError,ValueError): raise ValueError('days must be a whole number')
    if days < 0: raise ValueError('days cannot be negative')
    if days > 36500: raise ValueError('days exceeds maximum supported duration')
    if p not in XRAY_TAGS and p not in ('Hysteria','SSH'): raise ValueError('invalid protocol')
    # SSH quota accounting is not currently supported, but accept the field
    # from CLI clients for compatibility and keep the stored quota at zero.
    if p=='SSH':
        q=0
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',u): raise ValueError('invalid username')
    secret=str(d.get('secret') or (str(uuid.uuid4()) if p in ('VLESS','VMess') else secrets.token_urlsafe(18)))
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
        if p=='SSH':
            add_ssh(u,secret,days)
            ssh_created=True
        elif p!='Hysteria':
            add_xray(p,u,secret)
            xray_created=True
        c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at) values(?,?,?,?,?,?)',(u,p,secret,q,exp,int(time.time())))
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

def account_enable_error(row):
    now=int(time.time())
    if row['expiry'] and row['expiry']<=now:
        return 'account has expired; renew it before enabling'
    if row['quota_bytes'] and int(row['used_bytes'] or 0)>=int(row['quota_bytes']):
        return 'account quota has been reached; renew it before enabling'
    return None

def service_state(name):
    try:
        return subprocess.check_output(['systemctl','is-active',name],stderr=subprocess.DEVNULL,text=True).strip()
    except Exception:
        return 'unknown'

class H(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def do_GET(self):
        if self.path=='/health': return send(self,{'ok':True})
        if self.path in ('/','/setup') and not admin_configured(): return _setup_page(self)
        if self.path=='/setup':
            self.send_response(404); self.end_headers(); return
        if not auth(self.headers):
            self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return
        if self.path=='/api/backup':
            files=[]
            for path in sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)[:10]:
                try:
                    files.append({'name':os.path.basename(path),'size':os.path.getsize(path),'created_at':int(os.path.getmtime(path))})
                except OSError: pass
            return send(self,{'backups':files})

        if self.path=='/api/users':
            c=conn(); rows=[record(x) for x in c.execute('select * from users order by id desc')]; c.close()
            now=int(time.time())
            for x in rows:
                x['days_remaining']=None if not x['expiry'] else max(int((x['expiry']-now)/86400),0)
                x['expiry_warning']=bool(x['expiry'] and x['expiry']<=now+7*86400)
            return send(self,rows)
        if self.path=='/api/usage-history':
            c=conn()
            rows=c.execute('select day,bytes from usage_daily order by day desc limit 30').fetchall()
            c.close()
            rows=list(reversed(rows))
            return send(self,{'values':[int(x['bytes'] or 0) for x in rows],'days':[x['day'] for x in rows]})

        if self.path=='/api/usage':
            c=conn()
            rows=c.execute('select id,username,protocol,used_bytes,daily_used_bytes,quota_bytes,usage_day from users order by id desc').fetchall()
            srv=c.execute('select * from server_usage where id=1').fetchone()
            c.close()
            data={
                'updated_at':int(time.time()),
                'server':{
                    'daily_bytes':int(srv['daily_bytes'] if srv else 0),
                    'all_time_bytes':int(srv['all_time_bytes'] if srv else 0),
                },
                'ssh_per_user_metered':False,
                'accounts':[
                    {
                        'id':int(r['id']),
                        'username':r['username'],
                        'protocol':r['protocol'],
                        'daily_bytes':int(r['daily_used_bytes'] or 0),
                        'all_time_bytes':int(r['used_bytes'] or 0),
                        'quota_bytes':int(r['quota_bytes'] or 0),
                        'usage_day':r['usage_day'] or ''
                    } for r in rows
                ]
            }
            return send(self,data)
        if self.path=='/api/metrics':
            return send(self,_system_metrics())

        if self.path=='/api/sessions':
            return send(self,{'updated_at':int(time.time()),'sessions':_active_sessions()})

        if self.path=='/api/security':
            return send(self,_security_info())

        if self.path=='/api/certificate':
            return send(self,_certificate_info())

        if self.path=='/api/events':
            c=conn()
            rows=c.execute('select id,created_at,action,username,details from events order by id desc limit 100').fetchall()
            c.close()
            return send(self,{'events':[dict(x) for x in rows]})

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
            counts={p:sum(1 for x in rows if x['protocol']==p) for p in ('SSH','VLESS','VMess','Trojan','Hysteria')}
            active=sum(1 for x in rows if x['enabled'])
            total_used=sum(int(x['used_bytes'] or 0) for x in rows)
            total_daily=sum(int(x['daily_used_bytes'] or 0) for x in rows)
            usage_conn=conn()
            srv_row=usage_conn.execute('select * from server_usage where id=1').fetchone()
            server_daily=int(srv_row['daily_bytes'] if srv_row else 0)
            server_all=int(srv_row['all_time_bytes'] if srv_row else 0)
            usage_conn.close()
            services={
                'SSH':service_state('ssh'),
                'NGINX':service_state('nginx'),
                'HAProxy':service_state('haproxy'),
                'Xray':service_state('xray'),
                'Hysteria 2':service_state('hysteria-server'),
                'Panel':service_state('unified-vps-panel')
            }
            reboot='04:00 local' if os.path.exists('/etc/cron.d/unified-vps-daily-reboot') else 'Not configured'

            def state_badge(state):
                cls='up' if state=='active' else 'down'
                return f'<span class="status {cls}"><span class="dot"></span>{html.escape(state.upper())}</span>'

            rows_html=[]
            for x in rows:
                xid=x['id']; protocol=x['protocol']; username=html.escape(x['username'],quote=True)
                secret=html.escape(str(x['secret']),quote=True)
                enabled=bool(x['enabled'])
                enabled_label='Enabled' if enabled else 'Disabled'
                action='disable' if enabled else 'enable'
                action_label='Disable' if enabled else 'Enable'
                expiry='Unlimited' if not x['expiry'] else time.strftime('%Y-%m-%d %H:%M',time.localtime(x['expiry']))
                used=f"{x['used_bytes']/(1024**3):.2f} GB"
                daily=f"{x['daily_used_bytes']/(1024**3):.2f} GB"
                quota='Unlimited' if not x['quota_bytes'] else f"{x['quota_bytes']/(1024**3):.2f} GB"
                usage_text = "Not metered" if protocol=='SSH' else used
                daily_text = "Today: not metered" if protocol=='SSH' else f"Today: {daily}"
                if protocol in XRAY_TAGS:
                    uris=[]
                    for port in ('80','443'):
                        uri=html.escape(x['uris'].get(port,''),quote=True)
                        uris.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy {port}</button></div>')
                    connection='<div class="uri-stack">'+''.join(uris)+'</div>'
                elif protocol=='SSH':
                    parts=[]
                    for label,key in (('WS 80','WebSocket'),('WS 8080','WebSocket8080'),('WS 8880','WebSocket8880'),('WSS 443','WebSocketTLS'),('WSS 8443','WebSocketTLS8443')):
                        uri=html.escape(x['uris'].get(key,''),quote=True)
                        parts.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy</button></div>')
                    connection=f'<div class="sshmeta"><span>Host: {html.escape(x["host"],quote=True)}</span><span>Path: {html.escape(x["uris"].get("Path","/ssh"),quote=True)}</span></div><div class="uri-stack">{"".join(parts)}</div>'
                else:
                    uri=html.escape(next(iter(x['uris'].values()),''),quote=True)
                    connection=f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy URI</button></div>'
                rows_html.append(
                    f'<tr data-row data-id="{xid}" data-user="{username}" data-protocol="{html.escape(protocol.lower())}">'
                    f'<td><input class="rowcheck" type="checkbox" value="{xid}"></td><td><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{username}</strong><span class="muted">{html.escape(protocol)}</span></div></div></td>'
                    f'<td>{state_badge("active" if enabled else "disabled")}</td>'
                    f'<td><span class="pill">{html.escape(str(x["port"]))}</span></td>'
                    f'<td><button class="secret-btn" data-secret="{secret}" type="button">Reveal</button></td>'
                    f'<td><span id="alltime-{xid}">{usage_text}</span><span class="muted"> / {quota}</span><span id="daily-{xid}" class="muted">{daily_text}</span></td>'
                    f'<td><span class="muted {"warn" if x["expiry"] and x["expiry"]<=time.time()+7*86400 else ""}">{html.escape(expiry)}</span>{("<span class=\"muted warn\">Expires soon</span>" if x["expiry"] and x["expiry"]<=time.time()+7*86400 else "")}</td>'
                    f'<td>{connection}</td>'
                    f'<td><div class="actions"><button class="ghost" data-action="{action}" data-id="{xid}" type="button">{action_label}</button><button class="ghost" data-renew="{xid}" type="button">Renew</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div></td>'
                    f'</tr>'
                )

            rows_html=''.join(rows_html) or '<tr><td colspan="9"><div class="empty">No accounts yet. Create the first account above.</div></td></tr>'
            cards_html=[]
            for x in rows:
                xid=x['id']; protocol=x['protocol']; enabled=bool(x['enabled'])
                expiry='Unlimited' if not x['expiry'] else time.strftime('%Y-%m-%d',time.localtime(x['expiry']))
                usage='Not metered' if protocol=='SSH' else _human_bytes(x['used_bytes'])
                today='Not metered' if protocol=='SSH' else _human_bytes(x['daily_used_bytes'])
                expiry_warn=bool(x['expiry'] and x['expiry']<=time.time()+7*86400)
                cards_html.append(
                    f'<article class="account-card" data-card-user="{html.escape(x["username"],quote=True)}" data-card-protocol="{html.escape(protocol.lower())}">'
                    f'<div class="cardtop"><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{html.escape(x["username"])}</strong><span class="muted">{html.escape(protocol)}</span></div></div>{state_badge("active" if enabled else "disabled")}</div>'
                    f'<div class="cardstats"><div><span>Today</span><strong>{today}</strong></div><div><span>All time</span><strong>{usage}</strong></div><div><span>Expiry</span><strong class="{"warn" if expiry_warn else ""}">{html.escape(expiry)}</strong></div></div>'
                    f'<div class="cardactions"><button class="ghost" data-action="{"disable" if enabled else "enable"}" data-id="{xid}" type="button">{"Disable" if enabled else "Enable"}</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div>'
                    f'</article>'
                )
            cards_html=''.join(cards_html) or '<div class="empty">No accounts yet.</div>'
            service_html=''.join(f'<div class="service-card"><span>{html.escape(k)}</span>{state_badge(v)}</div>' for k,v in services.items())

            page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#06110b">
<title>Unified VPS — Control Center</title>
<style>
:root{--bg:#06110b;--panel:#0b1811;--panel2:#0e2116;--line:#173524;--text:#ecfff2;--muted:#87a995;--accent:#42f58d;--accent2:#14c96b;--danger:#ff6b78;--shadow:0 24px 70px rgba(0,0,0,.38)}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 500px at 80% -10%,rgba(66,245,141,.09),transparent 60%),radial-gradient(700px 400px at 5% 0,rgba(20,201,107,.07),transparent 60%),var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button{cursor:pointer}
.app{min-height:100vh;display:grid;grid-template-columns:240px 1fr}
.sidebar{position:sticky;top:0;height:100vh;padding:24px 16px;border-right:1px solid var(--line);background:rgba(4,13,8,.78);backdrop-filter:blur(18px)}
.brand{display:flex;gap:12px;align-items:center;padding:8px 10px 24px}.brandmark{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#42f58d,#0d7f45);color:#031108;font-weight:900;box-shadow:0 10px 28px rgba(66,245,141,.18)}.brand h1{font-size:14px;margin:0}.brand p{margin:2px 0 0;color:var(--muted);font-size:11px}
.nav{display:grid;gap:6px}.nav a{padding:11px 12px;border-radius:10px;color:#a9c5b2;text-decoration:none}.nav a.active,.nav a:hover{background:rgba(66,245,141,.08);color:var(--text)}
.sidefoot{position:absolute;bottom:20px;left:16px;right:16px;padding:12px;border:1px solid var(--line);border-radius:12px;background:rgba(13,33,22,.55)}.sidefoot .label{font-size:11px;color:var(--muted)}.sidefoot strong{display:block;margin-top:3px;font-size:13px}
.main{min-width:0}.topbar{height:72px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;border-bottom:1px solid var(--line);background:rgba(6,17,11,.58);backdrop-filter:blur(18px);position:sticky;top:0;z-index:10}.topbar h2{margin:0;font-size:18px}.topbar p{margin:2px 0 0;color:var(--muted);font-size:12px}.top-actions{display:flex;align-items:center;gap:10px}.badge{padding:7px 10px;border:1px solid var(--line);background:rgba(255,255,255,.02);border-radius:999px;color:var(--muted);font-size:11px}
.content{padding:26px;max-width:1500px;margin:auto}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:20px}.hero h3{font-size:28px;margin:0}.hero p{margin:5px 0 0;color:var(--muted)}.primary{border:0;border-radius:11px;padding:11px 15px;background:linear-gradient(135deg,var(--accent),#1dbb68);color:#03200f;font-weight:800;box-shadow:0 12px 32px rgba(66,245,141,.16)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.stat,.panel{border:1px solid var(--line);background:linear-gradient(180deg,rgba(14,33,22,.9),rgba(8,20,13,.9));border-radius:16px;box-shadow:var(--shadow)}.stat{padding:16px}.stat .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.stat .v{font-size:28px;font-weight:800;margin-top:6px}.stat .s{color:#a6c3b0;font-size:11px;margin-top:4px}
.grid2{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;margin-top:14px}.panel{padding:18px}.panelhead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}.panelhead h4{margin:0;font-size:14px}.panelhead p{margin:3px 0 0;color:var(--muted);font-size:11px}
.services{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.service-card{display:flex;align-items:center;justify-content:space-between;padding:11px 12px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.02)}.status{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:5px 8px;font-size:10px;font-weight:800;letter-spacing:.06em}.status.up{background:rgba(66,245,141,.08);color:var(--accent)}.status.down{background:rgba(255,107,120,.08);color:var(--danger)}.dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 12px currentColor}
.matrix{display:grid;gap:8px}.matrix div{display:flex;justify-content:space-between;padding:10px 12px;border:1px solid var(--line);border-radius:10px}.matrix span:last-child{color:var(--accent);font-weight:700}
.accounts{margin-top:14px}.toolbar{display:flex;gap:10px;flex-wrap:wrap}.search{min-width:240px;flex:1;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:#08140c;color:var(--text);outline:none}.select{padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:#08140c;color:var(--text)}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:1080px}th,td{padding:12px 13px;text-align:left;border-bottom:1px solid rgba(23,53,36,.72);vertical-align:top}th{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;background:#09170f}tr:last-child td{border-bottom:0}
.usercell{display:flex;align-items:center;gap:9px}.avatar{width:31px;height:31px;border-radius:9px;display:grid;place-items:center;background:rgba(66,245,141,.1);color:var(--accent);font-weight:800}.usercell strong{display:block}.muted{display:block;color:var(--muted);font-size:11px}.pill{display:inline-block;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.04);font-size:10px;color:#bcd4c4}
.copyline{display:flex;align-items:center;gap:7px;margin:5px 0;max-width:480px}.copyline code{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;padding:7px 9px;border:1px solid var(--line);border-radius:8px;background:#06100a;color:#bdeccf;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.copy-btn,.ghost,.danger,.secret-btn{border:1px solid var(--line);border-radius:8px;padding:7px 9px;background:#0a170f;color:#bfe4ca;font-size:11px}.copy-btn:hover,.ghost:hover,.secret-btn:hover{border-color:#2e754c;color:var(--text)}.danger{color:#ff9da6;border-color:rgba(255,107,120,.24)}.danger:hover{background:rgba(255,107,120,.08)}.actions{display:flex;gap:6px;flex-wrap:wrap}.sshmeta{display:flex;gap:10px;flex-wrap:wrap;color:var(--muted);font-size:11px}.empty{text-align:center;color:var(--muted);padding:30px}
.overlay{position:fixed;inset:0;background:rgba(1,7,4,.72);backdrop-filter:blur(10px);display:none;align-items:center;justify-content:center;padding:20px;z-index:30}.overlay.open{display:flex}.modal{width:min(560px,100%);background:#09170f;border:1px solid var(--line);border-radius:18px;box-shadow:0 30px 90px rgba(0,0,0,.5);padding:20px}.modalhead{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px}.modalhead h3{margin:0}.modalhead p{margin:4px 0;color:var(--muted);font-size:12px}.close{border:1px solid var(--line);background:#07110b;color:#b4c9bc;border-radius:8px;padding:6px 9px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{display:grid;gap:6px}.field.full{grid-column:1/-1}.field label{font-size:11px;color:var(--muted)}.field input,.field select{padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#06100a;color:var(--text);outline:none}.modalfoot{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}.secondary{border:1px solid var(--line);background:#08140c;color:#b9d0c2;border-radius:10px;padding:10px 13px}
.toast{position:fixed;right:20px;bottom:20px;z-index:50;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:#0c1d13;color:var(--text);box-shadow:var(--shadow);display:none}.toast.show{display:block}.account-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:14px}.account-card{border:1px solid var(--line);border-radius:14px;padding:14px;background:linear-gradient(180deg,rgba(15,36,24,.78),rgba(7,18,12,.78))}.cardtop{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.cardstats{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin:13px 0}.cardstats div{padding:8px;border-radius:9px;background:rgba(255,255,255,.025);border:1px solid var(--line)}.cardstats span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase}.cardstats strong{display:block;margin-top:3px;font-size:11px}.cardactions{display:flex;gap:7px}.account-card .danger{margin-left:auto}.eventlist{display:grid;gap:7px;max-height:260px;overflow:auto}.event{padding:9px 10px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.02)}.event strong{font-size:11px}.event small{display:block;color:var(--muted);margin-top:2px}.warn{color:#ffd166!important}.dangertext{color:var(--danger)!important}.metric-good{color:var(--accent)!important}
@media(max-width:1050px){.app{grid-template-columns:1fr}.sidebar{display:none}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}.account-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar{padding:0 16px}.content{padding:18px}}
@media(max-width:620px){.stats{grid-template-columns:1fr}.account-cards{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero h3{font-size:23px}.formgrid{grid-template-columns:1fr}.field.full{grid-column:auto}.top-actions .badge{display:none}}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand"><div class="brandmark">UV</div><div><h1>Unified VPS</h1><p>Control Center</p></div></div>
  <nav class="nav">
    <a class="active" href="#dashboard">Dashboard</a>
    <a href="#accounts">Accounts</a>
    <a href="#transports">Transports</a>
    <a href="#services">Services</a>
  </nav>
  <div class="sidefoot"><span class="label">DAILY REBOOT</span><strong>__REBOOT__</strong><span class="label">Panel access: __PANEL_URL__</span></div>
</aside>
<main class="main">
  <header class="topbar"><div><h2>Command Center</h2><p>__DOMAIN__</p></div><div class="top-actions"><span class="badge">IPv4 __IP__</span><span class="badge">__OS__</span></div></header>
  <section class="content" id="dashboard">
    <div class="hero"><div><h3>Server overview</h3><p>Live account inventory, services and transport endpoints.</p><span id="usageStamp" class="muted" style="margin-top:6px">Usage updating…</span></div><button class="primary" id="openCreate" type="button">+ Create account</button></div>
    <div class="stats">
      <div class="stat"><div class="k">Total accounts</div><div class="v">__TOTAL__</div><div class="s">All protocols</div></div>
      <div class="stat"><div class="k">Active accounts</div><div class="v">__ACTIVE__</div><div class="s">Currently enabled</div></div>
      <div class="stat"><div class="k">Server traffic today</div><div class="v" id="serverDaily">__SERVER_DAILY__</div><div class="s">Live interface accounting</div></div>
      <div class="stat"><div class="k">Server traffic all time</div><div class="v" id="serverAll">__SERVER_ALL__</div><div class="s">Persistent total</div></div>
      <div class="stat"><div class="k">Daily reboot</div><div class="v" style="font-size:20px">__REBOOT__</div><div class="s">Automatic maintenance</div></div>
      <div class="stat"><div class="k">CPU load</div><div class="v" id="cpuLoad">—</div><div class="s">Live 10s telemetry</div></div>
      <div class="stat"><div class="k">Memory</div><div class="v" id="memUse">—</div><div class="s">Used / total</div></div>
      <div class="stat"><div class="k">Disk</div><div class="v" id="diskUse">—</div><div class="s">Used / total</div></div>
    </div>
    <div class="grid2" id="services">
      <section class="panel"><div class="panelhead"><div><h4>Service health</h4><p>Critical components detected by systemd.</p></div></div><div class="services">__SERVICES__</div></section>
      <section class="panel" id="transports"><div class="panelhead"><div><h4>Transport matrix</h4><p>Public listeners exposed by Unified VPS.</p></div></div>
        <div class="matrix">
          <div><span>SSH over WebSocket</span><span>80 / 8080 / 8880</span></div>
          <div><span>SSH over WSS</span><span>443 / 8443</span></div>
          <div><span>SSH raw TCP</span><span>143 / 8080 / 8443</span></div>
          <div><span>VLESS / VMess / Trojan</span><span>80 / 443</span></div>
          <div><span>Hysteria 2</span><span>UDP 53</span></div>
          <div><span>Web panel</span><span>TCP 6080</span></div>
        </div>
      </section>
    </div>
    <div class="grid2">
      <section class="panel">
        <div class="panelhead"><div><h4>Live network</h4><p>Interface throughput and active TCP sessions.</p></div></div>
        <div class="matrix">
          <div><span>Download / RX</span><span id="rxRate">—</span></div>
          <div><span>Upload / TX</span><span id="txRate">—</span></div>
          <div><span>Active sessions</span><span id="sessionCount">—</span></div>
          <div><span>Certificate</span><span id="certState">Checking…</span></div>
          <div><span>Fail2Ban</span><span id="f2bState">Checking…</span></div>
        </div>
      </section>
      <section class="panel">
        <div class="panelhead"><div><h4>System activity</h4><p>Recent account and maintenance events.</p></div></div>
        <div id="events" class="eventlist"><div class="muted">Loading events…</div></div>
      </section>
    </div>
    <section class="panel" id="sessionsPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Active connections</h4><p>Current established TCP sessions visible to the server.</p></div><button class="secondary" id="refreshSessions" type="button">Refresh</button></div>
      <div class="tablewrap"><table style="min-width:760px"><thead><tr><th>Process</th><th>User</th><th>Local</th><th>Remote</th><th>PID</th></tr></thead><tbody id="sessionsBody"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></div>
    </section>
    <section class="panel" id="securityPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Security center</h4><p>SSH protection, firewall and certificate posture.</p></div></div>
      <div class="services" id="securityGrid"><div class="service-card">Loading…</div></div>
    </section>
    <section class="panel" id="activityPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Usage history</h4><p>Server traffic is persisted daily and all-time.</p></div></div>
      <canvas id="usageChart" height="120" style="width:100%;display:block"></canvas>
    </section>
    <section class="panel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Account expiry</h4><p>Accounts expiring within the next seven days.</p></div></div>
      <div id="expiryList" class="services"><div class="muted">Checking expiries…</div></div>
    </section>
    <section class="panel accounts" id="accounts">
      <div class="panelhead"><div><h4>Account management</h4><p>Create, renew, enable, disable and copy connection credentials.</p></div>
        <div class="toolbar"><input class="search" id="search" placeholder="Search username or protocol…"><select class="select" id="filter"><option value="">All protocols</option><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select><button class="secondary" id="bulkEnable" type="button">Enable selected</button><button class="secondary" id="bulkDisable" type="button">Disable selected</button><button class="danger" id="bulkDelete" type="button">Delete selected</button><button class="secondary" id="backupNow" type="button">Backup</button><button class="secondary" id="restoreLatest" type="button">Restore latest</button><button class="secondary" id="renewCert" type="button">Renew certificate</button><button class="secondary" id="speedtest" type="button">Run speedtest</button></div>
      </div>
      <pre id="speedout" style="display:none;max-height:260px;overflow:auto;padding:12px;border:1px solid var(--line);border-radius:10px;background:#06100a;color:#bcebcf;font-size:11px"></pre>
      <div class="account-cards" id="accountCards">__ACCOUNT_CARDS__</div>
      <div class="tablewrap"><table><thead><tr><th><input id="selectAll" type="checkbox" title="Select all"></th><th>Account</th><th>Status</th><th>Ports</th><th>Secret</th><th>Usage</th><th>Expiry</th><th>Connection URI</th><th>Actions</th></tr></thead><tbody id="accountsBody">__ROWS__</tbody></table></div>
    </section>
  </section>
</main>
</div>

<div class="overlay" id="modal">
  <div class="modal">
    <div class="modalhead"><div><h3>Create account</h3><p>Provision a new Unified VPS identity.</p></div><button class="close" id="closeCreate" type="button">Close</button></div>
    <form id="createForm">
      <div class="formgrid">
        <div class="field"><label>Username</label><input name="username" required maxlength="32"></div>
        <div class="field"><label>Protocol</label><select name="protocol" id="protocol"><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select></div>
        <div class="field full" id="sshSecretField"><label>SSH password</label><input name="secret" id="sshSecret" type="password" autocomplete="new-password"></div>
        <div class="field"><label>Duration (days)</label><input name="days" type="number" min="0" value="0"></div>
        <div class="field"><label>Quota (GB)</label><input name="quota_gb" id="quota" type="number" min="0" step="0.1" value="0"></div>
      </div>
      <div class="modalfoot"><button class="secondary" id="cancelCreate" type="button">Cancel</button><button class="primary" type="submit">Create account</button></div>
    </form>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const $=s=>document.querySelector(s);
function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2200)}
async function copyText(value,button){
  let ok=false;
  try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(value);ok=true}}catch(e){}
  if(!ok){
    const ta=document.createElement("textarea");ta.value=value;ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);ta.focus();ta.select();
    try{ok=document.execCommand("copy")}catch(e){ok=false}ta.remove();
  }
  if(ok){const old=button.textContent;button.textContent="Copied";setTimeout(()=>button.textContent=old,1200)}else{toast("Copy blocked — URI selected for manual copy.")}
}
document.addEventListener("click",async e=>{
  const copy=e.target.closest("[data-copy]"); if(copy){await copyText(copy.dataset.copy,copy);return}
  const reveal=e.target.closest(".secret-btn"); if(reveal){if(reveal.dataset.revealed==="1"){reveal.textContent="Reveal";reveal.dataset.revealed="0"}else{reveal.textContent=reveal.dataset.secret;reveal.dataset.revealed="1"}return}
  const act=e.target.closest("[data-action]"); if(act){
    const id=act.dataset.id, action=act.dataset.action;
    const r=await fetch("/api/users/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(id),action:action})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Action failed");return} location.reload(); return
  }
  const del=e.target.closest("[data-delete]"); if(del){
    if(!confirm("Delete this account permanently?")) return;
    const r=await fetch("/api/users/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(del.dataset.delete)})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Delete failed");return} location.reload(); return
  }
  const renew=e.target.closest("[data-renew]"); if(renew){
    const days=prompt("Renew for how many days?","30"); if(!days||!/^\\d+$/.test(days)||Number(days)<1)return;
    const r=await fetch("/api/users/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(renew.dataset.renew),action:"renew",days:Number(days)})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Renewal failed");return} location.reload(); return
  }
});
$("#openCreate").onclick=()=>$("#modal").classList.add("open");
$("#closeCreate").onclick=$("#cancelCreate").onclick=()=>$("#modal").classList.remove("open");
const protocol=$("#protocol"), sshField=$("#sshSecretField"), sshSecret=$("#sshSecret"), quota=$("#quota");
function updateFields(){const ssh=protocol.value==="SSH";sshField.style.display=ssh?"grid":"none";sshSecret.required=ssh;quota.disabled=ssh;if(ssh)quota.value="0"}
protocol.onchange=updateFields;updateFields();
$("#createForm").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.target), payload=Object.fromEntries(f.entries());
  payload.days=Number(payload.days||0);payload.quota_gb=Number(payload.quota_gb||0);
  const r=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const j=await r.json(); if(!r.ok){toast(j.error||"Account creation failed");return} location.reload();
};
$("#search").oninput=$("#filter").onchange=()=>{
  const q=$("#search").value.toLowerCase(), p=$("#filter").value.toLowerCase();
  document.querySelectorAll("[data-row]").forEach(r=>{const hit=(!q||(r.dataset.user||"").includes(q)||(r.dataset.protocol||"").includes(q))&&(!p||(r.dataset.protocol||"")===p);r.style.display=hit?"":"none"});
  document.querySelectorAll("[data-card-user]").forEach(r=>{const hit=(!q||(r.dataset.cardUser||"").includes(q)||(r.dataset.cardProtocol||"").includes(q))&&(!p||(r.dataset.cardProtocol||"")===p);r.style.display=hit?"":"none"});
};
async function selectedIds(){return [...document.querySelectorAll(".rowcheck:checked")].map(x=>Number(x.value)).filter(Boolean)}
async function bulk(action){
  const ids=await selectedIds(); if(!ids.length){toast("Select at least one account");return}
  let days=0;if(action==="renew"){days=Number(prompt("Renew selected accounts for how many days?","30")||0);if(!days)return}
  if(action==="delete"&&!confirm("Delete "+ids.length+" selected accounts permanently?"))return;
  const r=await fetch("/api/users/bulk",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids,action,days})});
  const j=await r.json();if(!r.ok){toast(j.error||"Bulk action failed");return}location.reload();
}
$("#selectAll").onchange=e=>document.querySelectorAll(".rowcheck").forEach(x=>x.checked=e.target.checked);
$("#bulkEnable").onclick=()=>bulk("enable");$("#bulkDisable").onclick=()=>bulk("disable");$("#bulkDelete").onclick=()=>bulk("delete");
$("#backupNow").onclick=async()=>{const r=await fetch("/api/backup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"create"})});const j=await r.json();toast(r.ok?"Backup created":(j.error||"Backup failed"));refreshEvents()};
$("#restoreLatest").onclick=async()=>{if(!confirm("Restore the latest backup and restart core services?"))return;const r=await fetch("/api/backup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"restore"})});const j=await r.json();toast(r.ok?"Restore complete":(j.error||"Restore failed"));if(r.ok)setTimeout(()=>location.reload(),2500)};
$("#renewCert").onclick=async()=>{if(!confirm("Force certificate renewal now?"))return;const r=await fetch("/api/certificate/renew",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});const j=await r.json();toast(r.ok?"Certificate renewed":(j.error||"Renewal failed"));refreshSecurity()};
async function refreshExpiry(){
  try{
    const r=await fetch("/api/users",{cache:"no-store"});if(!r.ok)return;const rows=await r.json(), box=document.getElementById("expiryList");if(!box)return;
    const soon=rows.filter(x=>x.days_remaining!==null&&x.days_remaining<=7);
    box.innerHTML=soon.length?soon.map(x=>"<div class='service-card'><span>"+x.username+" • "+x.protocol+"</span><strong class='"+(x.days_remaining<=1?"dangertext":"warn")+"'>"+(x.days_remaining===0?"Expires today":x.days_remaining+" days")+"</strong></div>").join(""):"<div class='muted'>No accounts expire within seven days.</div>";
  }catch(_){}
}
refreshExpiry();setInterval(refreshExpiry,30000);
$("#speedtest").onclick=async()=>{
  const out=$("#speedout");out.style.display="block";out.textContent="Running Ookla Speedtest…";
  const r=await fetch("/api/speedtest"),j=await r.json();out.textContent=j.output||j.error||"No result";
};

function fmtBytes(n){
  n=Math.max(Number(n||0),0);
  const u=["B","KB","MB","GB","TB","PB"]; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return n.toFixed(2)+" "+u[i];
}
async function refreshUsage(){
  try{
    const r=await fetch("/api/usage",{cache:"no-store"}); if(!r.ok)return;
    const j=await r.json();
    const sd=document.getElementById("serverDaily"), sa=document.getElementById("serverAll");
    if(sd)sd.textContent=fmtBytes(j.server.daily_bytes);
    if(sa)sa.textContent=fmtBytes(j.server.all_time_bytes);
    for(const a of j.accounts||[]){
      const all=document.getElementById("alltime-"+a.id), daily=document.getElementById("daily-"+a.id);
      if(a.protocol==="SSH") continue;
      if(all)all.textContent=fmtBytes(a.all_time_bytes);
      if(daily)daily.textContent="Today: "+fmtBytes(a.daily_bytes);
    }
    const stamp=document.getElementById("usageStamp");
    if(stamp)stamp.textContent="Usage updated "+new Date((j.updated_at||Date.now()/1000)*1000).toLocaleTimeString();
  }catch(_){}
}
refreshUsage();
setInterval(refreshUsage,10000);

function fmtRate(n){return fmtBytes(Number(n||0))+"/s"}
async function refreshMetrics(){
  try{
    const r=await fetch("/api/metrics",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const load=(j.cpu_load||[0])[0], mem=j.memory||{}, disk=j.disk||{}, net=j.network||{};
    const cpu=document.getElementById("cpuLoad"), mm=document.getElementById("memUse"), dd=document.getElementById("diskUse");
    if(cpu)cpu.textContent=Number(load||0).toFixed(2);
    if(mm)mm.textContent=fmtBytes(mem.used||0)+" / "+fmtBytes(mem.total||0);
    if(dd)dd.textContent=fmtBytes(disk.used||0)+" / "+fmtBytes(disk.total||0);
    const rx=document.getElementById("rxRate"),tx=document.getElementById("txRate");
    if(rx)rx.textContent=fmtRate(net.rx_bps);
    if(tx)tx.textContent=fmtRate(net.tx_bps);
  }catch(_){}
}
async function refreshSessions(){
  try{
    const r=await fetch("/api/sessions",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const body=document.getElementById("sessionsBody"); if(!body)return;
    const rows=j.sessions||[];
    document.getElementById("sessionCount").textContent=String(rows.length);
    body.innerHTML=rows.length?rows.map(x=>"<tr><td>"+(x.process||"—")+"</td><td>"+(x.user||"—")+"</td><td>"+(x.local||"—")+"</td><td>"+(x.remote||"—")+"</td><td>"+(x.pid||"—")+"</td></tr>").join(""):"<tr><td colspan='5' class='muted'>No established TCP sessions.</td></tr>";
  }catch(_){}
}
async function refreshSecurity(){
  try{
    const [s,c]=await Promise.all([fetch("/api/security",{cache:"no-store"}),fetch("/api/certificate",{cache:"no-store"})]);
    const j=await s.json(), cert=await c.json();
    const fs=document.getElementById("f2bState"), cs=document.getElementById("certState");
    if(fs)fs.textContent=(j.fail2ban||"unknown").toUpperCase()+" • "+(j.banned||0)+" banned";
    if(cs){cs.textContent=cert.ok?(cert.days_remaining+" days remaining"):"Unavailable";cs.className=cert.ok&&cert.days_remaining>14?"metric-good":(cert.days_remaining>=0?"warn":"dangertext")}
    const g=document.getElementById("securityGrid");
    if(g)g.innerHTML=[
      ["Fail2Ban",String(j.fail2ban||"unknown").toUpperCase()],
      ["Banned IPs",String(j.banned||0)],
      ["SSH failures / 24h",String(j.failed_ssh_24h||0)],
      ["Firewall rules",String(j.firewall_rules||0)],
      ["SSH password auth",String((j.ssh_auth||{}).passwordauthentication||"unknown").toUpperCase()],
      ["Certificate",cert.ok?(cert.days_remaining+" days left"):"Unavailable"]
    ].map(x=>"<div class='service-card'><span>"+x[0]+"</span><strong>"+x[1]+"</strong></div>").join("");
  }catch(_){}
}
async function refreshEvents(){
  try{
    const r=await fetch("/api/events",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const e=document.getElementById("events"); if(!e)return;
    e.innerHTML=(j.events||[]).slice(0,30).map(x=>"<div class='event'><strong>"+x.action+(x.username?" • "+x.username:"")+"</strong><small>"+new Date(x.created_at*1000).toLocaleString()+" "+(x.details||"")+"</small></div>").join("")||"<div class='muted'>No activity yet.</div>";
  }catch(_){}
}
function drawUsageChart(data){
  const canvas=document.getElementById("usageChart"); if(!canvas)return;
  const ctx=canvas.getContext("2d"),w=canvas.clientWidth||600,h=120,dpr=window.devicePixelRatio||1;
  canvas.width=w*dpr;canvas.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
  ctx.strokeStyle="rgba(66,245,141,.18)";ctx.lineWidth=1;
  for(let y=20;y<h;y+=25){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  if(!data.length)return;
  const max=Math.max(...data,1), step=w/Math.max(data.length-1,1);
  ctx.strokeStyle="#42f58d";ctx.lineWidth=2;ctx.beginPath();
  data.forEach((v,i)=>{const x=i*step,y=h-10-(v/max)*(h-25);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke();
}
async function refreshChart(){
  try{
    const r=await fetch("/api/usage-history",{cache:"no-store"});if(!r.ok)return;const j=await r.json();drawUsageChart(j.values||[]);
  }catch(_){}
}
refreshMetrics();refreshSessions();refreshSecurity();refreshEvents();refreshChart();
setInterval(refreshMetrics,10000);setInterval(refreshSessions,10000);setInterval(refreshSecurity,30000);setInterval(refreshEvents,15000);setInterval(refreshChart,60000);
document.getElementById("refreshSessions").onclick=refreshSessions;
</script>
</body></html>"""
            page=page.replace('__ROWS__',rows_html)
            page=page.replace('__ACCOUNT_CARDS__',cards_html)
            page=page.replace('__SERVICES__',service_html)
            page=page.replace('__REBOOT__',html.escape(reboot,quote=True))
            page=page.replace('__PANEL_URL__',html.escape(f'http://{public_host()}:{PORT}/',quote=True))
            page=page.replace('__DOMAIN__',html.escape(public_host()))
            page=page.replace('__IP__',html.escape(public_ip()))
            os_name=os.uname().sysname+' '+os.uname().release
            try:
                with open('/etc/os-release') as fh:
                    vals={}
                    for line in fh:
                        if '=' in line:
                            k,v=line.rstrip().split('=',1)
                            vals[k]=v.strip().strip('"')
                os_name=vals.get('PRETTY_NAME',os_name)
            except Exception:
                pass
            page=page.replace('__OS__',html.escape(os_name))
            page=page.replace('__TOTAL__',str(len(rows)))
            page=page.replace('__ACTIVE__',str(active))
            page=page.replace('__SERVER_DAILY__',_human_bytes(server_daily))
            page=page.replace('__SERVER_ALL__',_human_bytes(server_all))
            b=page.encode()

            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path=='/setup':
            try: d=body(self)
            except ValueError as e: return send(self,{'error':str(e)},400)
            except Exception: return send(self,{'error':'invalid JSON'},400)
            username=str(d.get('username','')).strip()
            password=str(d.get('password',''))
            confirm=str(d.get('confirm',''))
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',username): return send(self,{'error':'Username must contain only letters, numbers, dots, underscores or hyphens.'},400)
            if username.lower()=='spiderman': return send(self,{'error':'Choose a different username.'},400)
            if len(password)<8 or len(password)>128 or '\n' in password or '\r' in password or '\x00' in password: return send(self,{'error':'Password must be 8-128 characters and cannot contain newlines.'},400)
            if password!=confirm: return send(self,{'error':'Passwords do not match.'},400)
            try:
                with SETUP_LOCK:
                    if admin_configured(): return send(self,{'error':'Initial setup has already been completed.'},409)
                    _save_admin_credentials(username,password)
                    cookie=_session_cookie(username)
                payload=json.dumps({'ok':True,'message':'Credentials saved. Logging in.'}).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Cache-Control','no-store')
                self.send_header('Set-Cookie',f'{SESSION_COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
            except Exception as e: return send(self,{'error':str(e)},500)
            return
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
        except ValueError as e: return send(self,{'error':str(e)},400)
        except Exception: return send(self,{'error':'invalid JSON'},400)

        if self.path=='/api/backup':
            action=str(d.get('action','')).lower()
            if action=='create':
                try:
                    p=subprocess.run(['/usr/local/sbin/unified-vps-backup'],capture_output=True,text=True,timeout=120)
                    if p.returncode: return send(self,{'error':(p.stderr or p.stdout).strip() or 'backup failed'},500)
                    log_event('backup_created',os.path.basename(p.stdout.strip()),'')
                    return send(self,{'ok':True,'path':p.stdout.strip()})
                except Exception as e: return send(self,{'error':str(e)},500)
            if action=='restore':
                files=sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)
                if not files: return send(self,{'error':'no backup available'},404)
                p=subprocess.run(['tar','-tzf',files[0]],capture_output=True,text=True,timeout=30)
                if p.returncode: return send(self,{'error':'latest backup is invalid'},500)
                p=subprocess.run(['tar','-xzf',files[0],'-C','/'],capture_output=True,text=True,timeout=120)
                if p.returncode: return send(self,{'error':(p.stderr or 'restore failed').strip()},500)
                log_event('backup_restored',os.path.basename(files[0]),'')
                result=send(self,{'ok':True,'path':files[0],'message':'Restore applied; services will restart shortly.'})
                def restart_restored_services():
                    subprocess.run(['systemctl','daemon-reload'],capture_output=True)
                    subprocess.run(['systemctl','restart','nginx','xray','hysteria-server','haproxy','unified-vps-panel','unified-vps-wstunnel-ssh','unified-vps-ws-payload-ssh'],capture_output=True)
                threading.Timer(2.0,restart_restored_services).start()
                return result
            return send(self,{'error':'unsupported backup action'},400)

        if self.path=='/api/certificate/renew':
            with CERT_LOCK:
                haproxy_was_active=subprocess.run(['systemctl','is-active','--quiet','haproxy'],check=False).returncode==0
                try:
                    acme='/root/.acme.sh/acme.sh'
                    if not os.path.exists(acme): return send(self,{'error':'acme.sh not installed'},500)
                    renew_args=[acme,'--renew','-d',public_host(),'--force']
                    if haproxy_was_active:
                        renew_args += ['--pre-hook','systemctl stop haproxy','--post-hook','systemctl start haproxy']
                    p=subprocess.run(renew_args,capture_output=True,text=True,timeout=180)
                    if p.returncode:
                        return send(self,{'error':(p.stderr or p.stdout).strip() or 'certificate renewal failed'},500)
                    log_event('certificate_renewed',public_host(),'')
                    return send(self,{'ok':True,'output':(p.stdout or '').strip()})
                except Exception as e:
                    return send(self,{'error':str(e)},500)
                finally:
                    if haproxy_was_active:
                        subprocess.run(['systemctl','start','haproxy'],capture_output=True)

        if self.path=='/api/users':
            try: return send(self,create_user(d))
            except Exception as e: return send(self,{'error':str(e)},500)
        if self.path=='/api/users/bulk':
            ids=[int(x) for x in d.get('ids',[]) if str(x).isdigit()]
            action=str(d.get('action','')).lower()
            if not ids or action not in ('enable','disable','delete','renew'):
                return send(self,{'error':'invalid bulk request'},400)
            if action=='renew':
                try: renew_days=int(d.get('days',0) or 0)
                except (TypeError,ValueError): return send(self,{'error':'renewal days required'},400)
                if renew_days<=0 or renew_days>36500: return send(self,{'error':'renewal days must be between 1 and 36500'},400)
            results=[]
            for uid in ids:
                try:
                    c=conn(); row=c.execute('select * from users where id=?',(uid,)).fetchone(); c.close()
                    if not row: results.append({'id':uid,'ok':False,'error':'not found'}); continue
                    if action=='delete':
                        if row['protocol']=='SSH': del_ssh(row['username'])
                        elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
                        else: del_xray(row['protocol'],row['username'])
                        c=conn(); c.execute('delete from users where id=?',(uid,)); c.commit(); c.close()
                    elif action in ('enable','disable'):
                        enable=action=='enable'
                        if enable:
                            err=account_enable_error(row)
                            if err: raise ValueError(err)
                        if row['protocol'] in XRAY_TAGS:
                            if enable: ensure_xray_client(row['protocol'],row['username'],row['secret'])
                            else: del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='Hysteria' and not enable:
                            kick_hysteria(row['username'])
                        elif row['protocol']=='SSH': set_ssh_enabled(row['username'],enable,row['expiry'])
                        c=conn(); c.execute('update users set enabled=? where id=?',(1 if enable else 0,uid)); c.commit(); c.close()
                    else:
                        days=int(d.get('days',0));
                        if days <= 0: raise ValueError('renewal days must be greater than 0')
                        exp=int(time.time())+days*86400
                        if row['protocol'] in XRAY_TAGS:
                            ensure_xray_client(row['protocol'],row['username'],row['secret'])
                        elif row['protocol']=='SSH':
                            set_ssh_enabled(row['username'],True,exp)
                        baseline=int(row['raw_bytes'] or 0)
                        if row['protocol']=='Hysteria':
                            hstats=_hysteria_usage()
                            if isinstance(hstats,dict): baseline=int(hstats.get(row['username'],baseline))
                        elif row['protocol'] in XRAY_TAGS:
                            baseline=0
                        c=conn(); c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',(exp,baseline,time.strftime('%Y-%m-%d'),uid)); c.commit(); c.close()
                    log_event('bulk_'+action,row['protocol'],row['username'])
                    results.append({'id':uid,'ok':True})
                except Exception as e:
                    results.append({'id':uid,'ok':False,'error':str(e)})
            return send(self,{'ok':all(x['ok'] for x in results),'results':results})

        if self.path=='/api/users/action':
            c=conn(); row=c.execute('select * from users where id=?',(int(d.get('id',0)),)).fetchone()
            if not row: c.close(); return send(self,{'error':'not found'},404)
            action=str(d.get('action','')).lower()
            try:
                if action=='renew':
                    days=int(d.get('days',0) or 0)
                    if days <= 0: raise ValueError('renewal days must be greater than 0')
                    if days > 36500: raise ValueError('renewal days exceeds maximum supported duration')
                    exp=int(time.time())+days*86400
                    baseline=int(row['raw_bytes'] or 0)
                    if row['protocol']=='Hysteria':
                        hstats=_hysteria_usage()
                        if isinstance(hstats,dict): baseline=int(hstats.get(row['username'],baseline))
                    elif row['protocol'] in XRAY_TAGS:
                        baseline=0
                    c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',(exp,baseline,time.strftime('%Y-%m-%d'),row['id']))
                    if row['protocol'] in XRAY_TAGS:
                        ensure_xray_client(row['protocol'],row['username'],row['secret'])
                    elif row['protocol']=='SSH':
                        set_ssh_enabled(row['username'],True,exp)
                    c.commit()
                    log_event('account_renewed',f'{days} days',row['username'])
                    return send(self,{'ok':True,'action':'renew','id':row['id']})
                if action in ('enable','disable'):
                    enable=action=='enable'
                    if enable:
                        err=account_enable_error(row)
                        if err: raise ValueError(err)
                    if enable:
                        if row['protocol'] in XRAY_TAGS:
                            with XRAY_LOCK:
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
                            set_ssh_enabled(row['username'],True,row['expiry'])
                    else:
                        if row['protocol'] in XRAY_TAGS:
                            del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='Hysteria':
                            kick_hysteria(row['username'])
                        elif row['protocol']=='SSH':
                            set_ssh_enabled(row['username'],False)
                    c.execute('update users set enabled=? where id=?',(1 if enable else 0,row['id']))
                    c.commit()
                    log_event('account_'+action,row['protocol'],row['username'])
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
                elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
                else: del_xray(row['protocol'],row['username'])
                c.execute('delete from users where id=?',(row['id'],)); c.commit()
                log_event('account_deleted',row['protocol'],row['username'])
                return send(self,{'ok':True})
            except Exception as e: c.rollback(); return send(self,{'error':str(e)},500)
            finally: c.close()
        return send(self,{'error':'not found'},404)

if __name__=='__main__':
    conn().close()
    threading.Thread(target=sync_usage,daemon=True).start()
    ThreadingHTTPServer((os.environ.get('PANEL_BIND','0.0.0.0'),PORT),H).serve_forever()
,'\\        else:
            out.append(line)
    if not user_done: out.append('ADMIN_USER='+shlex.quote(username))
    if not pass_done: out.append('ADMIN_PASSWORD='+shlex.quote(password))
    tmp=PANEL_ENV+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: f.write('\n'.join(out)+'\n')
    os.chmod(tmp,0o600)
    os.replace(tmp,PANEL_ENV)
    ADMIN=username
    PASSWORD=password

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

def body(r):
    try:
        length=int(r.headers.get('Content-Length','0') or 0)
    except (TypeError,ValueError):
        raise ValueError('invalid content length')
    if length<0 or length>MAX_REQUEST_BODY:
        raise ValueError('request body too large')
    raw=r.rfile.read(length)
    return json.loads(raw or b'{}')

def public_host():
    return DOMAIN or public_ip()

def public_ip():
    global PUBLIC_IP_CACHE
    if PUBLIC_IP_CACHE: return PUBLIC_IP_CACHE
    try:
        value=subprocess.check_output(['curl','-4fsS','--max-time','3','https://api.ipify.org'],text=True).strip()
        if value:
            PUBLIC_IP_CACHE=value
            return value
    except Exception:
        pass
    return 'SERVER_IP'

def load_xray():
    with open(CFG) as f: return json.load(f)

def save_xray(d):
    with XRAY_LOCK:
        tmp=CFG+'.tmp.json'
        rollback=CFG+'.rollback.tmp'
        try:
            with open(CFG,'rb') as f: previous=f.read()
        except OSError:
            previous=None
        with open(tmp,'w') as f: json.dump(d,f,indent=2)
        test=subprocess.run(['xray','-test','-config',tmp],capture_output=True,text=True)
        if test.returncode:
            try: os.unlink(tmp)
            except OSError: pass
            raise RuntimeError('Xray configuration test failed: '+(test.stderr or test.stdout).strip())
        os.replace(tmp,CFG)
        rr=subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
        if rr.returncode:
            if previous is not None:
                try:
                    with open(rollback,'wb') as f: f.write(previous)
                    os.replace(rollback,CFG)
                    subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
                except Exception:
                    pass
            raise RuntimeError('Xray restart failed: '+(rr.stderr or rr.stdout).strip())

def add_xray(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray()
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            if any(c.get('email')==u for c in clients): raise RuntimeError('Username already exists in Xray')
            client={'email':u,'level':0}
            client['id' if protocol in ('VMess','VLESS') else 'password']=secret
            clients.append(client)
        save_xray(d)

def ensure_xray_client(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        key='id' if protocol in ('VMess','VLESS') else 'password'
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            client=next((x for x in clients if x.get('email')==u),None)
            if client is None:
                clients.append({'email':u,'level':0,key:secret}); changed=True
            elif client.get(key)!=secret:
                client[key]=secret; changed=True
        if changed: save_xray(d)

def del_xray(protocol,u):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib:
                old=len(ib['settings'].get('clients',[]))
                ib['settings']['clients']=[x for x in ib['settings'].get('clients',[]) if x.get('email')!=u]
                changed |= old != len(ib['settings']['clients'])
        if changed: save_xray(d)

def sync_ssh_expiry(u,expiry):
    if expiry:
        exp_date=time.strftime('%Y-%m-%d',time.localtime(int(expiry)+86400))
        subprocess.run(['chage','-E',exp_date,u],check=False)
    else:
        subprocess.run(['chage','-E','-1',u],check=False)

def set_ssh_enabled(u,enabled,expiry=None):
    p=subprocess.run(['usermod','-U' if enabled else '-L',u],capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to change SSH account state')
    if enabled and expiry is not None:
        sync_ssh_expiry(u,expiry)
    elif not enabled:
        subprocess.run(['pkill','-TERM','-u',u],capture_output=True)

def add_ssh(u,password,days):
    if subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError('Linux SSH username already exists')
    subprocess.run(['useradd','-m','-s','/bin/bash',u],check=True)
    p=subprocess.run(['chpasswd'],input=f'{u}:{password}\n',text=True,capture_output=True)
    if p.returncode:
        subprocess.run(['userdel','-r',u],capture_output=True)
        raise RuntimeError('Failed to set SSH password')
    subprocess.run(['usermod','-U',u],capture_output=True,check=False)
    sync_ssh_expiry(u, int(time.time())+days*86400 if days else 0)

def del_ssh(u):
    if subprocess.run(['id',u],capture_output=True).returncode != 0:
        return
    subprocess.run(['pkill','-TERM','-u',u],capture_output=True)
    p=subprocess.run(['userdel','-r',u],capture_output=True,text=True)
    if p.returncode and subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to delete SSH account')

def _xray_usage():
    try:
        p=subprocess.run(['xray','api','statsquery','--server=127.0.0.1:10085'],capture_output=True,text=True,timeout=10)
        if p.returncode != 0: return None
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
        return None

def _hysteria_request(path, method='GET', payload=None):
    if not HY2_STATS_SECRET:
        return None
    try:
        data=None
        headers={'Authorization':HY2_STATS_SECRET}
        if payload is not None:
            data=json.dumps(payload).encode()
            headers['Content-Type']='application/json'
        req=Request(f'http://127.0.0.1:9999{path}',data=data,headers=headers,method=method)
        with urlopen(req,timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None

def kick_hysteria(username):
    return _hysteria_request('/kick','POST',[str(username)]) is not None

def _hysteria_usage():
    data=_hysteria_request('/traffic')
    if data is None: return None
    if not isinstance(data,dict): return {}
    return {str(k): int(v.get('tx',0))+int(v.get('rx',0)) for k,v in data.items() if isinstance(v,dict)}

def _primary_interface():
    try:
        out=subprocess.check_output(['ip','route','show','default'],text=True,timeout=3)
        parts=out.split()
        return parts[parts.index('dev')+1] if 'dev' in parts else ''
    except Exception:
        return ''

def _server_bytes():
    iface=_primary_interface()
    if not iface: return 0,0
    try:
        with open(f'/sys/class/net/{iface}/statistics/rx_bytes') as f: rx=int(f.read().strip())
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes') as f: tx=int(f.read().strip())
        return rx,tx
    except Exception:
        return 0,0

def _human_bytes(n):
    n=float(max(int(n or 0),0))
    units=('B','KB','MB','GB','TB','PB')
    for u in units:
        if n < 1024 or u==units[-1]:
            return f'{n:.2f} {u}'
        n/=1024
    return '0.00 B'

def log_event(action, details='', username=''):
    try:
        c=conn()
        c.execute('insert into events(created_at,action,username,details) values(?,?,?,?)',
                  (int(time.time()),str(action),str(username),str(details)))
        c.execute('delete from events where id not in (select id from events order by id desc limit 500)')
        c.commit(); c.close()
    except Exception:
        pass

def _network_rate():
    iface=_primary_interface()
    if not iface:
        return {'rx_bytes':0,'tx_bytes':0,'rx_bps':0,'tx_bps':0}
    try:
        with open(f'/sys/class/net/{iface}/statistics/rx_bytes') as f: rx=int(f.read())
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes') as f: tx=int(f.read())
        now=time.time()
        prev=getattr(_network_rate,'prev',None)
        _network_rate.prev=(now,rx,tx)
        if not prev:
            return {'rx_bytes':rx,'tx_bytes':tx,'rx_bps':0,'tx_bps':0}
        dt=max(now-prev[0],0.1)
        return {'rx_bytes':rx,'tx_bytes':tx,'rx_bps':max(rx-prev[1],0)/dt,'tx_bps':max(tx-prev[2],0)/dt}
    except Exception:
        return {'rx_bytes':0,'tx_bytes':0,'rx_bps':0,'tx_bps':0}

def _system_metrics():
    try:
        load=os.getloadavg()
    except Exception:
        load=(0,0,0)
    mem={}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k,v=line.split(':',1)
                mem[k]=int(v.strip().split()[0])*1024
    except Exception:
        pass
    total=mem.get('MemTotal',0); available=mem.get('MemAvailable',0)
    used=max(total-available,0)
    du=__import__('shutil').disk_usage('/')
    net=_network_rate()
    return {
        'timestamp':int(time.time()),
        'cpu_load':[round(float(x),2) for x in load],
        'cpu_count':os.cpu_count() or 1,
        'memory':{'total':total,'used':used,'available':available},
        'disk':{'total':du.total,'used':du.used,'free':du.free},
        'network':net,
        'uptime_seconds':int(time.time()-__import__('psutil').boot_time()) if __import__('importlib').util.find_spec('psutil') else 0
    }

def _active_sessions():
    out=[]
    try:
        p=subprocess.run(['ss','-Hntp','state','established'],capture_output=True,text=True,timeout=5)
        for line in p.stdout.splitlines():
            parts=line.split()
            if len(parts)<5: continue
            local=parts[2]; peer=parts[3]
            proc=''
            pid=None
            m=re.search(r'users:\(\("([^"]+)",pid=(\d+)',line)
            if m:
                proc=m.group(1); pid=int(m.group(2))
            user=''
            if pid:
                try: user=subprocess.check_output(['ps','-o','user=','-p',str(pid)],text=True).strip()
                except Exception: pass
            out.append({'local':local,'remote':peer,'process':proc,'pid':pid,'user':user})
            if len(out)>=100: break
    except Exception:
        pass
    return out

def _certificate_info():
    path='/etc/unified-vps/xray.crt'
    if not os.path.exists(path): return {'ok':False,'error':'Certificate not found'}
    try:
        p=subprocess.run(['openssl','x509','-in',path,'-noout','-subject','-issuer','-startdate','-enddate'],
                         capture_output=True,text=True,timeout=5)
        vals={}
        for line in p.stdout.splitlines():
            if '=' in line:
                k,v=line.split('=',1); vals[k.strip()]=v.strip()
        end=vals.get('notAfter','')
        epoch=0
        if end:
            epoch=int(time.mktime(time.strptime(end,'%b %d %H:%M:%S %Y %Z')))
        days=int((epoch-time.time())/86400) if epoch else -1
        return {'ok':p.returncode==0,'subject':vals.get('subject',''),'issuer':vals.get('issuer',''),
                'start':vals.get('notBefore',''),'expiry':end,'days_remaining':days}
    except Exception as e:
        return {'ok':False,'error':str(e)}

def _security_info():
    failed=0
    try:
        text=subprocess.check_output(['journalctl','-u','ssh','--since','24 hours ago','--no-pager'],text=True,stderr=subprocess.DEVNULL)
        failed=sum(1 for x in text.splitlines() if 'Failed password' in x or 'Invalid user' in x)
    except Exception: pass
    banned=0; f2b='inactive'
    try:
        f2b=service_state('fail2ban')
        text=subprocess.check_output(['fail2ban-client','status','sshd'],text=True,stderr=subprocess.DEVNULL)
        m=re.search(r'Currently banned:\s*(\d+)',text); banned=int(m.group(1)) if m else 0
    except Exception: pass
    try:
        fw=sum(1 for x in subprocess.check_output(['iptables','-S','INPUT'],text=True,stderr=subprocess.DEVNULL).splitlines() if x.strip())
    except Exception: fw=0
    try:
        ssh_cfg=subprocess.check_output(['sshd','-T'],text=True,stderr=subprocess.DEVNULL)
        auth_cfg={k:v for k,v in (line.split(None,1) for line in ssh_cfg.splitlines() if line.split(None,1)[0] in ('passwordauthentication','kbdinteractiveauthentication','usepam'))}
    except Exception: auth_cfg={}
    return {'fail2ban':f2b,'banned':banned,'failed_ssh_24h':failed,'firewall_rules':fw,'ssh_auth':auth_cfg}

def sync_usage():
    while True:
        try:
            xusage=_xray_usage()
            husage=_hysteria_usage()
            c=conn()
            rows=c.execute('select * from users').fetchall()
            now=int(time.time())
            today=time.strftime('%Y-%m-%d',time.localtime(now))
            disable=[]
            for row in rows:
                if row['protocol'] in XRAY_TAGS:
                    if xusage is None: continue
                    raw=xusage.get(row['username'],0)
                elif row['protocol']=='Hysteria':
                    if husage is None: continue
                    raw=husage.get(row['username'],0)
                else:
                    raw=0
                prev=int(row['raw_bytes'] or 0)
                delta=raw-prev if raw >= prev else raw
                used=int(row['used_bytes'] or 0)+delta
                daily=int(row['daily_used_bytes'] or 0)
                usage_day=row['usage_day'] or ''
                if usage_day != today:
                    daily=0
                daily += delta
                expired=bool(row['expiry'] and row['expiry']<=now)
                quota_hit=bool(row['quota_bytes'] and used>=row['quota_bytes'])
                if row['enabled'] and (expired or quota_hit):
                    disable.append(row)
                c.execute('update users set used_bytes=?,raw_bytes=?,daily_used_bytes=?,usage_day=? where id=?',
                          (used,raw,daily,today,row['id']))

            rx,tx=_server_bytes()
            srv=c.execute('select * from server_usage where id=1').fetchone()
            if srv:
                raw_rx=int(srv['raw_rx'] or 0); raw_tx=int(srv['raw_tx'] or 0)
                server_delta=(rx-raw_rx if rx >= raw_rx else rx)+(tx-raw_tx if tx >= raw_tx else tx)
                server_all=int(srv['all_time_bytes'] or 0)+server_delta
                server_daily=int(srv['daily_bytes'] or 0)
                if (srv['usage_day'] or '') != today:
                    server_daily=0
                server_daily += server_delta
                c.execute('update server_usage set raw_rx=?,raw_tx=?,all_time_bytes=?,daily_bytes=?,usage_day=? where id=1',
                          (rx,tx,server_all,server_daily,today))
                c.execute('insert into usage_daily(day,bytes) values(?,?) on conflict(day) do update set bytes=excluded.bytes',
                          (today,server_daily))
            c.commit(); c.close()

            xrows=[r for r in disable if r['protocol'] in XRAY_TAGS]
            if xrows:
                with XRAY_LOCK:
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
                log_event('account_auto_disabled','expired or quota reached',row['username'])
                if row['protocol']=='Hysteria':
                    kick_hysteria(row['username'])
                if row['protocol']=='SSH':
                    try: set_ssh_enabled(row['username'],False)
                    except Exception: pass
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
    except (TypeError,ValueError): raise ValueError('quota must be a finite non-negative number')
    if not math.isfinite(quota_gb) or quota_gb < 0: raise ValueError('quota must be a finite non-negative number')
    q=int(quota_gb*(1024**3))
    try: days=int(d.get('days',0) or 0)
    except (TypeError,ValueError): raise ValueError('days must be a whole number')
    if days < 0: raise ValueError('days cannot be negative')
    if days > 36500: raise ValueError('days exceeds maximum supported duration')
    if p not in XRAY_TAGS and p not in ('Hysteria','SSH'): raise ValueError('invalid protocol')
    # SSH quota accounting is not currently supported, but accept the field
    # from CLI clients for compatibility and keep the stored quota at zero.
    if p=='SSH':
        q=0
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',u): raise ValueError('invalid username')
    secret=str(d.get('secret') or (str(uuid.uuid4()) if p in ('VLESS','VMess') else secrets.token_urlsafe(18)))
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
        if p=='SSH':
            add_ssh(u,secret,days)
            ssh_created=True
        elif p!='Hysteria':
            add_xray(p,u,secret)
            xray_created=True
        c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at) values(?,?,?,?,?,?)',(u,p,secret,q,exp,int(time.time())))
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

def account_enable_error(row):
    now=int(time.time())
    if row['expiry'] and row['expiry']<=now:
        return 'account has expired; renew it before enabling'
    if row['quota_bytes'] and int(row['used_bytes'] or 0)>=int(row['quota_bytes']):
        return 'account quota has been reached; renew it before enabling'
    return None

def service_state(name):
    try:
        return subprocess.check_output(['systemctl','is-active',name],stderr=subprocess.DEVNULL,text=True).strip()
    except Exception:
        return 'unknown'

class H(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def do_GET(self):
        if self.path=='/health': return send(self,{'ok':True})
        if self.path in ('/','/setup') and not admin_configured(): return _setup_page(self)
        if self.path=='/setup':
            self.send_response(404); self.end_headers(); return
        if not auth(self.headers):
            self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return
        if self.path=='/api/backup':
            files=[]
            for path in sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)[:10]:
                try:
                    files.append({'name':os.path.basename(path),'size':os.path.getsize(path),'created_at':int(os.path.getmtime(path))})
                except OSError: pass
            return send(self,{'backups':files})

        if self.path=='/api/users':
            c=conn(); rows=[record(x) for x in c.execute('select * from users order by id desc')]; c.close()
            now=int(time.time())
            for x in rows:
                x['days_remaining']=None if not x['expiry'] else max(int((x['expiry']-now)/86400),0)
                x['expiry_warning']=bool(x['expiry'] and x['expiry']<=now+7*86400)
            return send(self,rows)
        if self.path=='/api/usage-history':
            c=conn()
            rows=c.execute('select day,bytes from usage_daily order by day desc limit 30').fetchall()
            c.close()
            rows=list(reversed(rows))
            return send(self,{'values':[int(x['bytes'] or 0) for x in rows],'days':[x['day'] for x in rows]})

        if self.path=='/api/usage':
            c=conn()
            rows=c.execute('select id,username,protocol,used_bytes,daily_used_bytes,quota_bytes,usage_day from users order by id desc').fetchall()
            srv=c.execute('select * from server_usage where id=1').fetchone()
            c.close()
            data={
                'updated_at':int(time.time()),
                'server':{
                    'daily_bytes':int(srv['daily_bytes'] if srv else 0),
                    'all_time_bytes':int(srv['all_time_bytes'] if srv else 0),
                },
                'ssh_per_user_metered':False,
                'accounts':[
                    {
                        'id':int(r['id']),
                        'username':r['username'],
                        'protocol':r['protocol'],
                        'daily_bytes':int(r['daily_used_bytes'] or 0),
                        'all_time_bytes':int(r['used_bytes'] or 0),
                        'quota_bytes':int(r['quota_bytes'] or 0),
                        'usage_day':r['usage_day'] or ''
                    } for r in rows
                ]
            }
            return send(self,data)
        if self.path=='/api/metrics':
            return send(self,_system_metrics())

        if self.path=='/api/sessions':
            return send(self,{'updated_at':int(time.time()),'sessions':_active_sessions()})

        if self.path=='/api/security':
            return send(self,_security_info())

        if self.path=='/api/certificate':
            return send(self,_certificate_info())

        if self.path=='/api/events':
            c=conn()
            rows=c.execute('select id,created_at,action,username,details from events order by id desc limit 100').fetchall()
            c.close()
            return send(self,{'events':[dict(x) for x in rows]})

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
            counts={p:sum(1 for x in rows if x['protocol']==p) for p in ('SSH','VLESS','VMess','Trojan','Hysteria')}
            active=sum(1 for x in rows if x['enabled'])
            total_used=sum(int(x['used_bytes'] or 0) for x in rows)
            total_daily=sum(int(x['daily_used_bytes'] or 0) for x in rows)
            usage_conn=conn()
            srv_row=usage_conn.execute('select * from server_usage where id=1').fetchone()
            server_daily=int(srv_row['daily_bytes'] if srv_row else 0)
            server_all=int(srv_row['all_time_bytes'] if srv_row else 0)
            usage_conn.close()
            services={
                'SSH':service_state('ssh'),
                'NGINX':service_state('nginx'),
                'HAProxy':service_state('haproxy'),
                'Xray':service_state('xray'),
                'Hysteria 2':service_state('hysteria-server'),
                'Panel':service_state('unified-vps-panel')
            }
            reboot='04:00 local' if os.path.exists('/etc/cron.d/unified-vps-daily-reboot') else 'Not configured'

            def state_badge(state):
                cls='up' if state=='active' else 'down'
                return f'<span class="status {cls}"><span class="dot"></span>{html.escape(state.upper())}</span>'

            rows_html=[]
            for x in rows:
                xid=x['id']; protocol=x['protocol']; username=html.escape(x['username'],quote=True)
                secret=html.escape(str(x['secret']),quote=True)
                enabled=bool(x['enabled'])
                enabled_label='Enabled' if enabled else 'Disabled'
                action='disable' if enabled else 'enable'
                action_label='Disable' if enabled else 'Enable'
                expiry='Unlimited' if not x['expiry'] else time.strftime('%Y-%m-%d %H:%M',time.localtime(x['expiry']))
                used=f"{x['used_bytes']/(1024**3):.2f} GB"
                daily=f"{x['daily_used_bytes']/(1024**3):.2f} GB"
                quota='Unlimited' if not x['quota_bytes'] else f"{x['quota_bytes']/(1024**3):.2f} GB"
                usage_text = "Not metered" if protocol=='SSH' else used
                daily_text = "Today: not metered" if protocol=='SSH' else f"Today: {daily}"
                if protocol in XRAY_TAGS:
                    uris=[]
                    for port in ('80','443'):
                        uri=html.escape(x['uris'].get(port,''),quote=True)
                        uris.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy {port}</button></div>')
                    connection='<div class="uri-stack">'+''.join(uris)+'</div>'
                elif protocol=='SSH':
                    parts=[]
                    for label,key in (('WS 80','WebSocket'),('WS 8080','WebSocket8080'),('WS 8880','WebSocket8880'),('WSS 443','WebSocketTLS'),('WSS 8443','WebSocketTLS8443')):
                        uri=html.escape(x['uris'].get(key,''),quote=True)
                        parts.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy</button></div>')
                    connection=f'<div class="sshmeta"><span>Host: {html.escape(x["host"],quote=True)}</span><span>Path: {html.escape(x["uris"].get("Path","/ssh"),quote=True)}</span></div><div class="uri-stack">{"".join(parts)}</div>'
                else:
                    uri=html.escape(next(iter(x['uris'].values()),''),quote=True)
                    connection=f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy URI</button></div>'
                rows_html.append(
                    f'<tr data-row data-id="{xid}" data-user="{username}" data-protocol="{html.escape(protocol.lower())}">'
                    f'<td><input class="rowcheck" type="checkbox" value="{xid}"></td><td><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{username}</strong><span class="muted">{html.escape(protocol)}</span></div></div></td>'
                    f'<td>{state_badge("active" if enabled else "disabled")}</td>'
                    f'<td><span class="pill">{html.escape(str(x["port"]))}</span></td>'
                    f'<td><button class="secret-btn" data-secret="{secret}" type="button">Reveal</button></td>'
                    f'<td><span id="alltime-{xid}">{usage_text}</span><span class="muted"> / {quota}</span><span id="daily-{xid}" class="muted">{daily_text}</span></td>'
                    f'<td><span class="muted {"warn" if x["expiry"] and x["expiry"]<=time.time()+7*86400 else ""}">{html.escape(expiry)}</span>{("<span class=\"muted warn\">Expires soon</span>" if x["expiry"] and x["expiry"]<=time.time()+7*86400 else "")}</td>'
                    f'<td>{connection}</td>'
                    f'<td><div class="actions"><button class="ghost" data-action="{action}" data-id="{xid}" type="button">{action_label}</button><button class="ghost" data-renew="{xid}" type="button">Renew</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div></td>'
                    f'</tr>'
                )

            rows_html=''.join(rows_html) or '<tr><td colspan="9"><div class="empty">No accounts yet. Create the first account above.</div></td></tr>'
            cards_html=[]
            for x in rows:
                xid=x['id']; protocol=x['protocol']; enabled=bool(x['enabled'])
                expiry='Unlimited' if not x['expiry'] else time.strftime('%Y-%m-%d',time.localtime(x['expiry']))
                usage='Not metered' if protocol=='SSH' else _human_bytes(x['used_bytes'])
                today='Not metered' if protocol=='SSH' else _human_bytes(x['daily_used_bytes'])
                expiry_warn=bool(x['expiry'] and x['expiry']<=time.time()+7*86400)
                cards_html.append(
                    f'<article class="account-card" data-card-user="{html.escape(x["username"],quote=True)}" data-card-protocol="{html.escape(protocol.lower())}">'
                    f'<div class="cardtop"><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{html.escape(x["username"])}</strong><span class="muted">{html.escape(protocol)}</span></div></div>{state_badge("active" if enabled else "disabled")}</div>'
                    f'<div class="cardstats"><div><span>Today</span><strong>{today}</strong></div><div><span>All time</span><strong>{usage}</strong></div><div><span>Expiry</span><strong class="{"warn" if expiry_warn else ""}">{html.escape(expiry)}</strong></div></div>'
                    f'<div class="cardactions"><button class="ghost" data-action="{"disable" if enabled else "enable"}" data-id="{xid}" type="button">{"Disable" if enabled else "Enable"}</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div>'
                    f'</article>'
                )
            cards_html=''.join(cards_html) or '<div class="empty">No accounts yet.</div>'
            service_html=''.join(f'<div class="service-card"><span>{html.escape(k)}</span>{state_badge(v)}</div>' for k,v in services.items())

            page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#06110b">
<title>Unified VPS — Control Center</title>
<style>
:root{--bg:#06110b;--panel:#0b1811;--panel2:#0e2116;--line:#173524;--text:#ecfff2;--muted:#87a995;--accent:#42f58d;--accent2:#14c96b;--danger:#ff6b78;--shadow:0 24px 70px rgba(0,0,0,.38)}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 500px at 80% -10%,rgba(66,245,141,.09),transparent 60%),radial-gradient(700px 400px at 5% 0,rgba(20,201,107,.07),transparent 60%),var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button{cursor:pointer}
.app{min-height:100vh;display:grid;grid-template-columns:240px 1fr}
.sidebar{position:sticky;top:0;height:100vh;padding:24px 16px;border-right:1px solid var(--line);background:rgba(4,13,8,.78);backdrop-filter:blur(18px)}
.brand{display:flex;gap:12px;align-items:center;padding:8px 10px 24px}.brandmark{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#42f58d,#0d7f45);color:#031108;font-weight:900;box-shadow:0 10px 28px rgba(66,245,141,.18)}.brand h1{font-size:14px;margin:0}.brand p{margin:2px 0 0;color:var(--muted);font-size:11px}
.nav{display:grid;gap:6px}.nav a{padding:11px 12px;border-radius:10px;color:#a9c5b2;text-decoration:none}.nav a.active,.nav a:hover{background:rgba(66,245,141,.08);color:var(--text)}
.sidefoot{position:absolute;bottom:20px;left:16px;right:16px;padding:12px;border:1px solid var(--line);border-radius:12px;background:rgba(13,33,22,.55)}.sidefoot .label{font-size:11px;color:var(--muted)}.sidefoot strong{display:block;margin-top:3px;font-size:13px}
.main{min-width:0}.topbar{height:72px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;border-bottom:1px solid var(--line);background:rgba(6,17,11,.58);backdrop-filter:blur(18px);position:sticky;top:0;z-index:10}.topbar h2{margin:0;font-size:18px}.topbar p{margin:2px 0 0;color:var(--muted);font-size:12px}.top-actions{display:flex;align-items:center;gap:10px}.badge{padding:7px 10px;border:1px solid var(--line);background:rgba(255,255,255,.02);border-radius:999px;color:var(--muted);font-size:11px}
.content{padding:26px;max-width:1500px;margin:auto}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:20px}.hero h3{font-size:28px;margin:0}.hero p{margin:5px 0 0;color:var(--muted)}.primary{border:0;border-radius:11px;padding:11px 15px;background:linear-gradient(135deg,var(--accent),#1dbb68);color:#03200f;font-weight:800;box-shadow:0 12px 32px rgba(66,245,141,.16)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.stat,.panel{border:1px solid var(--line);background:linear-gradient(180deg,rgba(14,33,22,.9),rgba(8,20,13,.9));border-radius:16px;box-shadow:var(--shadow)}.stat{padding:16px}.stat .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.stat .v{font-size:28px;font-weight:800;margin-top:6px}.stat .s{color:#a6c3b0;font-size:11px;margin-top:4px}
.grid2{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;margin-top:14px}.panel{padding:18px}.panelhead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}.panelhead h4{margin:0;font-size:14px}.panelhead p{margin:3px 0 0;color:var(--muted);font-size:11px}
.services{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.service-card{display:flex;align-items:center;justify-content:space-between;padding:11px 12px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.02)}.status{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:5px 8px;font-size:10px;font-weight:800;letter-spacing:.06em}.status.up{background:rgba(66,245,141,.08);color:var(--accent)}.status.down{background:rgba(255,107,120,.08);color:var(--danger)}.dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 12px currentColor}
.matrix{display:grid;gap:8px}.matrix div{display:flex;justify-content:space-between;padding:10px 12px;border:1px solid var(--line);border-radius:10px}.matrix span:last-child{color:var(--accent);font-weight:700}
.accounts{margin-top:14px}.toolbar{display:flex;gap:10px;flex-wrap:wrap}.search{min-width:240px;flex:1;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:#08140c;color:var(--text);outline:none}.select{padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:#08140c;color:var(--text)}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:1080px}th,td{padding:12px 13px;text-align:left;border-bottom:1px solid rgba(23,53,36,.72);vertical-align:top}th{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;background:#09170f}tr:last-child td{border-bottom:0}
.usercell{display:flex;align-items:center;gap:9px}.avatar{width:31px;height:31px;border-radius:9px;display:grid;place-items:center;background:rgba(66,245,141,.1);color:var(--accent);font-weight:800}.usercell strong{display:block}.muted{display:block;color:var(--muted);font-size:11px}.pill{display:inline-block;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.04);font-size:10px;color:#bcd4c4}
.copyline{display:flex;align-items:center;gap:7px;margin:5px 0;max-width:480px}.copyline code{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;padding:7px 9px;border:1px solid var(--line);border-radius:8px;background:#06100a;color:#bdeccf;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.copy-btn,.ghost,.danger,.secret-btn{border:1px solid var(--line);border-radius:8px;padding:7px 9px;background:#0a170f;color:#bfe4ca;font-size:11px}.copy-btn:hover,.ghost:hover,.secret-btn:hover{border-color:#2e754c;color:var(--text)}.danger{color:#ff9da6;border-color:rgba(255,107,120,.24)}.danger:hover{background:rgba(255,107,120,.08)}.actions{display:flex;gap:6px;flex-wrap:wrap}.sshmeta{display:flex;gap:10px;flex-wrap:wrap;color:var(--muted);font-size:11px}.empty{text-align:center;color:var(--muted);padding:30px}
.overlay{position:fixed;inset:0;background:rgba(1,7,4,.72);backdrop-filter:blur(10px);display:none;align-items:center;justify-content:center;padding:20px;z-index:30}.overlay.open{display:flex}.modal{width:min(560px,100%);background:#09170f;border:1px solid var(--line);border-radius:18px;box-shadow:0 30px 90px rgba(0,0,0,.5);padding:20px}.modalhead{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px}.modalhead h3{margin:0}.modalhead p{margin:4px 0;color:var(--muted);font-size:12px}.close{border:1px solid var(--line);background:#07110b;color:#b4c9bc;border-radius:8px;padding:6px 9px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{display:grid;gap:6px}.field.full{grid-column:1/-1}.field label{font-size:11px;color:var(--muted)}.field input,.field select{padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#06100a;color:var(--text);outline:none}.modalfoot{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}.secondary{border:1px solid var(--line);background:#08140c;color:#b9d0c2;border-radius:10px;padding:10px 13px}
.toast{position:fixed;right:20px;bottom:20px;z-index:50;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:#0c1d13;color:var(--text);box-shadow:var(--shadow);display:none}.toast.show{display:block}.account-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:14px}.account-card{border:1px solid var(--line);border-radius:14px;padding:14px;background:linear-gradient(180deg,rgba(15,36,24,.78),rgba(7,18,12,.78))}.cardtop{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.cardstats{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin:13px 0}.cardstats div{padding:8px;border-radius:9px;background:rgba(255,255,255,.025);border:1px solid var(--line)}.cardstats span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase}.cardstats strong{display:block;margin-top:3px;font-size:11px}.cardactions{display:flex;gap:7px}.account-card .danger{margin-left:auto}.eventlist{display:grid;gap:7px;max-height:260px;overflow:auto}.event{padding:9px 10px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.02)}.event strong{font-size:11px}.event small{display:block;color:var(--muted);margin-top:2px}.warn{color:#ffd166!important}.dangertext{color:var(--danger)!important}.metric-good{color:var(--accent)!important}
@media(max-width:1050px){.app{grid-template-columns:1fr}.sidebar{display:none}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}.account-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar{padding:0 16px}.content{padding:18px}}
@media(max-width:620px){.stats{grid-template-columns:1fr}.account-cards{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero h3{font-size:23px}.formgrid{grid-template-columns:1fr}.field.full{grid-column:auto}.top-actions .badge{display:none}}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand"><div class="brandmark">UV</div><div><h1>Unified VPS</h1><p>Control Center</p></div></div>
  <nav class="nav">
    <a class="active" href="#dashboard">Dashboard</a>
    <a href="#accounts">Accounts</a>
    <a href="#transports">Transports</a>
    <a href="#services">Services</a>
  </nav>
  <div class="sidefoot"><span class="label">DAILY REBOOT</span><strong>__REBOOT__</strong><span class="label">Panel access: __PANEL_URL__</span></div>
</aside>
<main class="main">
  <header class="topbar"><div><h2>Command Center</h2><p>__DOMAIN__</p></div><div class="top-actions"><span class="badge">IPv4 __IP__</span><span class="badge">__OS__</span></div></header>
  <section class="content" id="dashboard">
    <div class="hero"><div><h3>Server overview</h3><p>Live account inventory, services and transport endpoints.</p><span id="usageStamp" class="muted" style="margin-top:6px">Usage updating…</span></div><button class="primary" id="openCreate" type="button">+ Create account</button></div>
    <div class="stats">
      <div class="stat"><div class="k">Total accounts</div><div class="v">__TOTAL__</div><div class="s">All protocols</div></div>
      <div class="stat"><div class="k">Active accounts</div><div class="v">__ACTIVE__</div><div class="s">Currently enabled</div></div>
      <div class="stat"><div class="k">Server traffic today</div><div class="v" id="serverDaily">__SERVER_DAILY__</div><div class="s">Live interface accounting</div></div>
      <div class="stat"><div class="k">Server traffic all time</div><div class="v" id="serverAll">__SERVER_ALL__</div><div class="s">Persistent total</div></div>
      <div class="stat"><div class="k">Daily reboot</div><div class="v" style="font-size:20px">__REBOOT__</div><div class="s">Automatic maintenance</div></div>
      <div class="stat"><div class="k">CPU load</div><div class="v" id="cpuLoad">—</div><div class="s">Live 10s telemetry</div></div>
      <div class="stat"><div class="k">Memory</div><div class="v" id="memUse">—</div><div class="s">Used / total</div></div>
      <div class="stat"><div class="k">Disk</div><div class="v" id="diskUse">—</div><div class="s">Used / total</div></div>
    </div>
    <div class="grid2" id="services">
      <section class="panel"><div class="panelhead"><div><h4>Service health</h4><p>Critical components detected by systemd.</p></div></div><div class="services">__SERVICES__</div></section>
      <section class="panel" id="transports"><div class="panelhead"><div><h4>Transport matrix</h4><p>Public listeners exposed by Unified VPS.</p></div></div>
        <div class="matrix">
          <div><span>SSH over WebSocket</span><span>80 / 8080 / 8880</span></div>
          <div><span>SSH over WSS</span><span>443 / 8443</span></div>
          <div><span>SSH raw TCP</span><span>143 / 8080 / 8443</span></div>
          <div><span>VLESS / VMess / Trojan</span><span>80 / 443</span></div>
          <div><span>Hysteria 2</span><span>UDP 53</span></div>
          <div><span>Web panel</span><span>TCP 6080</span></div>
        </div>
      </section>
    </div>
    <div class="grid2">
      <section class="panel">
        <div class="panelhead"><div><h4>Live network</h4><p>Interface throughput and active TCP sessions.</p></div></div>
        <div class="matrix">
          <div><span>Download / RX</span><span id="rxRate">—</span></div>
          <div><span>Upload / TX</span><span id="txRate">—</span></div>
          <div><span>Active sessions</span><span id="sessionCount">—</span></div>
          <div><span>Certificate</span><span id="certState">Checking…</span></div>
          <div><span>Fail2Ban</span><span id="f2bState">Checking…</span></div>
        </div>
      </section>
      <section class="panel">
        <div class="panelhead"><div><h4>System activity</h4><p>Recent account and maintenance events.</p></div></div>
        <div id="events" class="eventlist"><div class="muted">Loading events…</div></div>
      </section>
    </div>
    <section class="panel" id="sessionsPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Active connections</h4><p>Current established TCP sessions visible to the server.</p></div><button class="secondary" id="refreshSessions" type="button">Refresh</button></div>
      <div class="tablewrap"><table style="min-width:760px"><thead><tr><th>Process</th><th>User</th><th>Local</th><th>Remote</th><th>PID</th></tr></thead><tbody id="sessionsBody"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></div>
    </section>
    <section class="panel" id="securityPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Security center</h4><p>SSH protection, firewall and certificate posture.</p></div></div>
      <div class="services" id="securityGrid"><div class="service-card">Loading…</div></div>
    </section>
    <section class="panel" id="activityPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Usage history</h4><p>Server traffic is persisted daily and all-time.</p></div></div>
      <canvas id="usageChart" height="120" style="width:100%;display:block"></canvas>
    </section>
    <section class="panel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Account expiry</h4><p>Accounts expiring within the next seven days.</p></div></div>
      <div id="expiryList" class="services"><div class="muted">Checking expiries…</div></div>
    </section>
    <section class="panel accounts" id="accounts">
      <div class="panelhead"><div><h4>Account management</h4><p>Create, renew, enable, disable and copy connection credentials.</p></div>
        <div class="toolbar"><input class="search" id="search" placeholder="Search username or protocol…"><select class="select" id="filter"><option value="">All protocols</option><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select><button class="secondary" id="bulkEnable" type="button">Enable selected</button><button class="secondary" id="bulkDisable" type="button">Disable selected</button><button class="danger" id="bulkDelete" type="button">Delete selected</button><button class="secondary" id="backupNow" type="button">Backup</button><button class="secondary" id="restoreLatest" type="button">Restore latest</button><button class="secondary" id="renewCert" type="button">Renew certificate</button><button class="secondary" id="speedtest" type="button">Run speedtest</button></div>
      </div>
      <pre id="speedout" style="display:none;max-height:260px;overflow:auto;padding:12px;border:1px solid var(--line);border-radius:10px;background:#06100a;color:#bcebcf;font-size:11px"></pre>
      <div class="account-cards" id="accountCards">__ACCOUNT_CARDS__</div>
      <div class="tablewrap"><table><thead><tr><th><input id="selectAll" type="checkbox" title="Select all"></th><th>Account</th><th>Status</th><th>Ports</th><th>Secret</th><th>Usage</th><th>Expiry</th><th>Connection URI</th><th>Actions</th></tr></thead><tbody id="accountsBody">__ROWS__</tbody></table></div>
    </section>
  </section>
</main>
</div>

<div class="overlay" id="modal">
  <div class="modal">
    <div class="modalhead"><div><h3>Create account</h3><p>Provision a new Unified VPS identity.</p></div><button class="close" id="closeCreate" type="button">Close</button></div>
    <form id="createForm">
      <div class="formgrid">
        <div class="field"><label>Username</label><input name="username" required maxlength="32"></div>
        <div class="field"><label>Protocol</label><select name="protocol" id="protocol"><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select></div>
        <div class="field full" id="sshSecretField"><label>SSH password</label><input name="secret" id="sshSecret" type="password" autocomplete="new-password"></div>
        <div class="field"><label>Duration (days)</label><input name="days" type="number" min="0" value="0"></div>
        <div class="field"><label>Quota (GB)</label><input name="quota_gb" id="quota" type="number" min="0" step="0.1" value="0"></div>
      </div>
      <div class="modalfoot"><button class="secondary" id="cancelCreate" type="button">Cancel</button><button class="primary" type="submit">Create account</button></div>
    </form>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const $=s=>document.querySelector(s);
function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2200)}
async function copyText(value,button){
  let ok=false;
  try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(value);ok=true}}catch(e){}
  if(!ok){
    const ta=document.createElement("textarea");ta.value=value;ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);ta.focus();ta.select();
    try{ok=document.execCommand("copy")}catch(e){ok=false}ta.remove();
  }
  if(ok){const old=button.textContent;button.textContent="Copied";setTimeout(()=>button.textContent=old,1200)}else{toast("Copy blocked — URI selected for manual copy.")}
}
document.addEventListener("click",async e=>{
  const copy=e.target.closest("[data-copy]"); if(copy){await copyText(copy.dataset.copy,copy);return}
  const reveal=e.target.closest(".secret-btn"); if(reveal){if(reveal.dataset.revealed==="1"){reveal.textContent="Reveal";reveal.dataset.revealed="0"}else{reveal.textContent=reveal.dataset.secret;reveal.dataset.revealed="1"}return}
  const act=e.target.closest("[data-action]"); if(act){
    const id=act.dataset.id, action=act.dataset.action;
    const r=await fetch("/api/users/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(id),action:action})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Action failed");return} location.reload(); return
  }
  const del=e.target.closest("[data-delete]"); if(del){
    if(!confirm("Delete this account permanently?")) return;
    const r=await fetch("/api/users/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(del.dataset.delete)})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Delete failed");return} location.reload(); return
  }
  const renew=e.target.closest("[data-renew]"); if(renew){
    const days=prompt("Renew for how many days?","30"); if(!days||!/^\\d+$/.test(days)||Number(days)<1)return;
    const r=await fetch("/api/users/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(renew.dataset.renew),action:"renew",days:Number(days)})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Renewal failed");return} location.reload(); return
  }
});
$("#openCreate").onclick=()=>$("#modal").classList.add("open");
$("#closeCreate").onclick=$("#cancelCreate").onclick=()=>$("#modal").classList.remove("open");
const protocol=$("#protocol"), sshField=$("#sshSecretField"), sshSecret=$("#sshSecret"), quota=$("#quota");
function updateFields(){const ssh=protocol.value==="SSH";sshField.style.display=ssh?"grid":"none";sshSecret.required=ssh;quota.disabled=ssh;if(ssh)quota.value="0"}
protocol.onchange=updateFields;updateFields();
$("#createForm").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.target), payload=Object.fromEntries(f.entries());
  payload.days=Number(payload.days||0);payload.quota_gb=Number(payload.quota_gb||0);
  const r=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const j=await r.json(); if(!r.ok){toast(j.error||"Account creation failed");return} location.reload();
};
$("#search").oninput=$("#filter").onchange=()=>{
  const q=$("#search").value.toLowerCase(), p=$("#filter").value.toLowerCase();
  document.querySelectorAll("[data-row]").forEach(r=>{const hit=(!q||(r.dataset.user||"").includes(q)||(r.dataset.protocol||"").includes(q))&&(!p||(r.dataset.protocol||"")===p);r.style.display=hit?"":"none"});
  document.querySelectorAll("[data-card-user]").forEach(r=>{const hit=(!q||(r.dataset.cardUser||"").includes(q)||(r.dataset.cardProtocol||"").includes(q))&&(!p||(r.dataset.cardProtocol||"")===p);r.style.display=hit?"":"none"});
};
async function selectedIds(){return [...document.querySelectorAll(".rowcheck:checked")].map(x=>Number(x.value)).filter(Boolean)}
async function bulk(action){
  const ids=await selectedIds(); if(!ids.length){toast("Select at least one account");return}
  let days=0;if(action==="renew"){days=Number(prompt("Renew selected accounts for how many days?","30")||0);if(!days)return}
  if(action==="delete"&&!confirm("Delete "+ids.length+" selected accounts permanently?"))return;
  const r=await fetch("/api/users/bulk",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids,action,days})});
  const j=await r.json();if(!r.ok){toast(j.error||"Bulk action failed");return}location.reload();
}
$("#selectAll").onchange=e=>document.querySelectorAll(".rowcheck").forEach(x=>x.checked=e.target.checked);
$("#bulkEnable").onclick=()=>bulk("enable");$("#bulkDisable").onclick=()=>bulk("disable");$("#bulkDelete").onclick=()=>bulk("delete");
$("#backupNow").onclick=async()=>{const r=await fetch("/api/backup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"create"})});const j=await r.json();toast(r.ok?"Backup created":(j.error||"Backup failed"));refreshEvents()};
$("#restoreLatest").onclick=async()=>{if(!confirm("Restore the latest backup and restart core services?"))return;const r=await fetch("/api/backup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"restore"})});const j=await r.json();toast(r.ok?"Restore complete":(j.error||"Restore failed"));if(r.ok)setTimeout(()=>location.reload(),2500)};
$("#renewCert").onclick=async()=>{if(!confirm("Force certificate renewal now?"))return;const r=await fetch("/api/certificate/renew",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});const j=await r.json();toast(r.ok?"Certificate renewed":(j.error||"Renewal failed"));refreshSecurity()};
async function refreshExpiry(){
  try{
    const r=await fetch("/api/users",{cache:"no-store"});if(!r.ok)return;const rows=await r.json(), box=document.getElementById("expiryList");if(!box)return;
    const soon=rows.filter(x=>x.days_remaining!==null&&x.days_remaining<=7);
    box.innerHTML=soon.length?soon.map(x=>"<div class='service-card'><span>"+x.username+" • "+x.protocol+"</span><strong class='"+(x.days_remaining<=1?"dangertext":"warn")+"'>"+(x.days_remaining===0?"Expires today":x.days_remaining+" days")+"</strong></div>").join(""):"<div class='muted'>No accounts expire within seven days.</div>";
  }catch(_){}
}
refreshExpiry();setInterval(refreshExpiry,30000);
$("#speedtest").onclick=async()=>{
  const out=$("#speedout");out.style.display="block";out.textContent="Running Ookla Speedtest…";
  const r=await fetch("/api/speedtest"),j=await r.json();out.textContent=j.output||j.error||"No result";
};

function fmtBytes(n){
  n=Math.max(Number(n||0),0);
  const u=["B","KB","MB","GB","TB","PB"]; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return n.toFixed(2)+" "+u[i];
}
async function refreshUsage(){
  try{
    const r=await fetch("/api/usage",{cache:"no-store"}); if(!r.ok)return;
    const j=await r.json();
    const sd=document.getElementById("serverDaily"), sa=document.getElementById("serverAll");
    if(sd)sd.textContent=fmtBytes(j.server.daily_bytes);
    if(sa)sa.textContent=fmtBytes(j.server.all_time_bytes);
    for(const a of j.accounts||[]){
      const all=document.getElementById("alltime-"+a.id), daily=document.getElementById("daily-"+a.id);
      if(a.protocol==="SSH") continue;
      if(all)all.textContent=fmtBytes(a.all_time_bytes);
      if(daily)daily.textContent="Today: "+fmtBytes(a.daily_bytes);
    }
    const stamp=document.getElementById("usageStamp");
    if(stamp)stamp.textContent="Usage updated "+new Date((j.updated_at||Date.now()/1000)*1000).toLocaleTimeString();
  }catch(_){}
}
refreshUsage();
setInterval(refreshUsage,10000);

function fmtRate(n){return fmtBytes(Number(n||0))+"/s"}
async function refreshMetrics(){
  try{
    const r=await fetch("/api/metrics",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const load=(j.cpu_load||[0])[0], mem=j.memory||{}, disk=j.disk||{}, net=j.network||{};
    const cpu=document.getElementById("cpuLoad"), mm=document.getElementById("memUse"), dd=document.getElementById("diskUse");
    if(cpu)cpu.textContent=Number(load||0).toFixed(2);
    if(mm)mm.textContent=fmtBytes(mem.used||0)+" / "+fmtBytes(mem.total||0);
    if(dd)dd.textContent=fmtBytes(disk.used||0)+" / "+fmtBytes(disk.total||0);
    const rx=document.getElementById("rxRate"),tx=document.getElementById("txRate");
    if(rx)rx.textContent=fmtRate(net.rx_bps);
    if(tx)tx.textContent=fmtRate(net.tx_bps);
  }catch(_){}
}
async function refreshSessions(){
  try{
    const r=await fetch("/api/sessions",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const body=document.getElementById("sessionsBody"); if(!body)return;
    const rows=j.sessions||[];
    document.getElementById("sessionCount").textContent=String(rows.length);
    body.innerHTML=rows.length?rows.map(x=>"<tr><td>"+(x.process||"—")+"</td><td>"+(x.user||"—")+"</td><td>"+(x.local||"—")+"</td><td>"+(x.remote||"—")+"</td><td>"+(x.pid||"—")+"</td></tr>").join(""):"<tr><td colspan='5' class='muted'>No established TCP sessions.</td></tr>";
  }catch(_){}
}
async function refreshSecurity(){
  try{
    const [s,c]=await Promise.all([fetch("/api/security",{cache:"no-store"}),fetch("/api/certificate",{cache:"no-store"})]);
    const j=await s.json(), cert=await c.json();
    const fs=document.getElementById("f2bState"), cs=document.getElementById("certState");
    if(fs)fs.textContent=(j.fail2ban||"unknown").toUpperCase()+" • "+(j.banned||0)+" banned";
    if(cs){cs.textContent=cert.ok?(cert.days_remaining+" days remaining"):"Unavailable";cs.className=cert.ok&&cert.days_remaining>14?"metric-good":(cert.days_remaining>=0?"warn":"dangertext")}
    const g=document.getElementById("securityGrid");
    if(g)g.innerHTML=[
      ["Fail2Ban",String(j.fail2ban||"unknown").toUpperCase()],
      ["Banned IPs",String(j.banned||0)],
      ["SSH failures / 24h",String(j.failed_ssh_24h||0)],
      ["Firewall rules",String(j.firewall_rules||0)],
      ["SSH password auth",String((j.ssh_auth||{}).passwordauthentication||"unknown").toUpperCase()],
      ["Certificate",cert.ok?(cert.days_remaining+" days left"):"Unavailable"]
    ].map(x=>"<div class='service-card'><span>"+x[0]+"</span><strong>"+x[1]+"</strong></div>").join("");
  }catch(_){}
}
async function refreshEvents(){
  try{
    const r=await fetch("/api/events",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const e=document.getElementById("events"); if(!e)return;
    e.innerHTML=(j.events||[]).slice(0,30).map(x=>"<div class='event'><strong>"+x.action+(x.username?" • "+x.username:"")+"</strong><small>"+new Date(x.created_at*1000).toLocaleString()+" "+(x.details||"")+"</small></div>").join("")||"<div class='muted'>No activity yet.</div>";
  }catch(_){}
}
function drawUsageChart(data){
  const canvas=document.getElementById("usageChart"); if(!canvas)return;
  const ctx=canvas.getContext("2d"),w=canvas.clientWidth||600,h=120,dpr=window.devicePixelRatio||1;
  canvas.width=w*dpr;canvas.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
  ctx.strokeStyle="rgba(66,245,141,.18)";ctx.lineWidth=1;
  for(let y=20;y<h;y+=25){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  if(!data.length)return;
  const max=Math.max(...data,1), step=w/Math.max(data.length-1,1);
  ctx.strokeStyle="#42f58d";ctx.lineWidth=2;ctx.beginPath();
  data.forEach((v,i)=>{const x=i*step,y=h-10-(v/max)*(h-25);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke();
}
async function refreshChart(){
  try{
    const r=await fetch("/api/usage-history",{cache:"no-store"});if(!r.ok)return;const j=await r.json();drawUsageChart(j.values||[]);
  }catch(_){}
}
refreshMetrics();refreshSessions();refreshSecurity();refreshEvents();refreshChart();
setInterval(refreshMetrics,10000);setInterval(refreshSessions,10000);setInterval(refreshSecurity,30000);setInterval(refreshEvents,15000);setInterval(refreshChart,60000);
document.getElementById("refreshSessions").onclick=refreshSessions;
</script>
</body></html>"""
            page=page.replace('__ROWS__',rows_html)
            page=page.replace('__ACCOUNT_CARDS__',cards_html)
            page=page.replace('__SERVICES__',service_html)
            page=page.replace('__REBOOT__',html.escape(reboot,quote=True))
            page=page.replace('__PANEL_URL__',html.escape(f'http://{public_host()}:{PORT}/',quote=True))
            page=page.replace('__DOMAIN__',html.escape(public_host()))
            page=page.replace('__IP__',html.escape(public_ip()))
            os_name=os.uname().sysname+' '+os.uname().release
            try:
                with open('/etc/os-release') as fh:
                    vals={}
                    for line in fh:
                        if '=' in line:
                            k,v=line.rstrip().split('=',1)
                            vals[k]=v.strip().strip('"')
                os_name=vals.get('PRETTY_NAME',os_name)
            except Exception:
                pass
            page=page.replace('__OS__',html.escape(os_name))
            page=page.replace('__TOTAL__',str(len(rows)))
            page=page.replace('__ACTIVE__',str(active))
            page=page.replace('__SERVER_DAILY__',_human_bytes(server_daily))
            page=page.replace('__SERVER_ALL__',_human_bytes(server_all))
            b=page.encode()

            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path=='/setup':
            try: d=body(self)
            except ValueError as e: return send(self,{'error':str(e)},400)
            except Exception: return send(self,{'error':'invalid JSON'},400)
            username=str(d.get('username','')).strip()
            password=str(d.get('password',''))
            confirm=str(d.get('confirm',''))
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',username): return send(self,{'error':'Username must contain only letters, numbers, dots, underscores or hyphens.'},400)
            if username.lower()=='spiderman': return send(self,{'error':'Choose a different username.'},400)
            if len(password)<8 or len(password)>128 or '\n' in password or '\r' in password or '\x00' in password: return send(self,{'error':'Password must be 8-128 characters and cannot contain newlines.'},400)
            if password!=confirm: return send(self,{'error':'Passwords do not match.'},400)
            try:
                with SETUP_LOCK:
                    if admin_configured(): return send(self,{'error':'Initial setup has already been completed.'},409)
                    _save_admin_credentials(username,password)
                    cookie=_session_cookie(username)
                payload=json.dumps({'ok':True,'message':'Credentials saved. Logging in.'}).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Cache-Control','no-store')
                self.send_header('Set-Cookie',f'{SESSION_COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
            except Exception as e: return send(self,{'error':str(e)},500)
            return
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
        except ValueError as e: return send(self,{'error':str(e)},400)
        except Exception: return send(self,{'error':'invalid JSON'},400)

        if self.path=='/api/backup':
            action=str(d.get('action','')).lower()
            if action=='create':
                try:
                    p=subprocess.run(['/usr/local/sbin/unified-vps-backup'],capture_output=True,text=True,timeout=120)
                    if p.returncode: return send(self,{'error':(p.stderr or p.stdout).strip() or 'backup failed'},500)
                    log_event('backup_created',os.path.basename(p.stdout.strip()),'')
                    return send(self,{'ok':True,'path':p.stdout.strip()})
                except Exception as e: return send(self,{'error':str(e)},500)
            if action=='restore':
                files=sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)
                if not files: return send(self,{'error':'no backup available'},404)
                p=subprocess.run(['tar','-tzf',files[0]],capture_output=True,text=True,timeout=30)
                if p.returncode: return send(self,{'error':'latest backup is invalid'},500)
                p=subprocess.run(['tar','-xzf',files[0],'-C','/'],capture_output=True,text=True,timeout=120)
                if p.returncode: return send(self,{'error':(p.stderr or 'restore failed').strip()},500)
                log_event('backup_restored',os.path.basename(files[0]),'')
                result=send(self,{'ok':True,'path':files[0],'message':'Restore applied; services will restart shortly.'})
                def restart_restored_services():
                    subprocess.run(['systemctl','daemon-reload'],capture_output=True)
                    subprocess.run(['systemctl','restart','nginx','xray','hysteria-server','haproxy','unified-vps-panel','unified-vps-wstunnel-ssh','unified-vps-ws-payload-ssh'],capture_output=True)
                threading.Timer(2.0,restart_restored_services).start()
                return result
            return send(self,{'error':'unsupported backup action'},400)

        if self.path=='/api/certificate/renew':
            with CERT_LOCK:
                haproxy_was_active=subprocess.run(['systemctl','is-active','--quiet','haproxy'],check=False).returncode==0
                try:
                    acme='/root/.acme.sh/acme.sh'
                    if not os.path.exists(acme): return send(self,{'error':'acme.sh not installed'},500)
                    renew_args=[acme,'--renew','-d',public_host(),'--force']
                    if haproxy_was_active:
                        renew_args += ['--pre-hook','systemctl stop haproxy','--post-hook','systemctl start haproxy']
                    p=subprocess.run(renew_args,capture_output=True,text=True,timeout=180)
                    if p.returncode:
                        return send(self,{'error':(p.stderr or p.stdout).strip() or 'certificate renewal failed'},500)
                    log_event('certificate_renewed',public_host(),'')
                    return send(self,{'ok':True,'output':(p.stdout or '').strip()})
                except Exception as e:
                    return send(self,{'error':str(e)},500)
                finally:
                    if haproxy_was_active:
                        subprocess.run(['systemctl','start','haproxy'],capture_output=True)

        if self.path=='/api/users':
            try: return send(self,create_user(d))
            except Exception as e: return send(self,{'error':str(e)},500)
        if self.path=='/api/users/bulk':
            ids=[int(x) for x in d.get('ids',[]) if str(x).isdigit()]
            action=str(d.get('action','')).lower()
            if not ids or action not in ('enable','disable','delete','renew'):
                return send(self,{'error':'invalid bulk request'},400)
            if action=='renew':
                try: renew_days=int(d.get('days',0) or 0)
                except (TypeError,ValueError): return send(self,{'error':'renewal days required'},400)
                if renew_days<=0 or renew_days>36500: return send(self,{'error':'renewal days must be between 1 and 36500'},400)
            results=[]
            for uid in ids:
                try:
                    c=conn(); row=c.execute('select * from users where id=?',(uid,)).fetchone(); c.close()
                    if not row: results.append({'id':uid,'ok':False,'error':'not found'}); continue
                    if action=='delete':
                        if row['protocol']=='SSH': del_ssh(row['username'])
                        elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
                        else: del_xray(row['protocol'],row['username'])
                        c=conn(); c.execute('delete from users where id=?',(uid,)); c.commit(); c.close()
                    elif action in ('enable','disable'):
                        enable=action=='enable'
                        if enable:
                            err=account_enable_error(row)
                            if err: raise ValueError(err)
                        if row['protocol'] in XRAY_TAGS:
                            if enable: ensure_xray_client(row['protocol'],row['username'],row['secret'])
                            else: del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='Hysteria' and not enable:
                            kick_hysteria(row['username'])
                        elif row['protocol']=='SSH': set_ssh_enabled(row['username'],enable,row['expiry'])
                        c=conn(); c.execute('update users set enabled=? where id=?',(1 if enable else 0,uid)); c.commit(); c.close()
                    else:
                        days=int(d.get('days',0));
                        if days <= 0: raise ValueError('renewal days must be greater than 0')
                        exp=int(time.time())+days*86400
                        if row['protocol'] in XRAY_TAGS:
                            ensure_xray_client(row['protocol'],row['username'],row['secret'])
                        elif row['protocol']=='SSH':
                            set_ssh_enabled(row['username'],True,exp)
                        baseline=int(row['raw_bytes'] or 0)
                        if row['protocol']=='Hysteria':
                            hstats=_hysteria_usage()
                            if isinstance(hstats,dict): baseline=int(hstats.get(row['username'],baseline))
                        elif row['protocol'] in XRAY_TAGS:
                            baseline=0
                        c=conn(); c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',(exp,baseline,time.strftime('%Y-%m-%d'),uid)); c.commit(); c.close()
                    log_event('bulk_'+action,row['protocol'],row['username'])
                    results.append({'id':uid,'ok':True})
                except Exception as e:
                    results.append({'id':uid,'ok':False,'error':str(e)})
            return send(self,{'ok':all(x['ok'] for x in results),'results':results})

        if self.path=='/api/users/action':
            c=conn(); row=c.execute('select * from users where id=?',(int(d.get('id',0)),)).fetchone()
            if not row: c.close(); return send(self,{'error':'not found'},404)
            action=str(d.get('action','')).lower()
            try:
                if action=='renew':
                    days=int(d.get('days',0) or 0)
                    if days <= 0: raise ValueError('renewal days must be greater than 0')
                    if days > 36500: raise ValueError('renewal days exceeds maximum supported duration')
                    exp=int(time.time())+days*86400
                    baseline=int(row['raw_bytes'] or 0)
                    if row['protocol']=='Hysteria':
                        hstats=_hysteria_usage()
                        if isinstance(hstats,dict): baseline=int(hstats.get(row['username'],baseline))
                    elif row['protocol'] in XRAY_TAGS:
                        baseline=0
                    c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',(exp,baseline,time.strftime('%Y-%m-%d'),row['id']))
                    if row['protocol'] in XRAY_TAGS:
                        ensure_xray_client(row['protocol'],row['username'],row['secret'])
                    elif row['protocol']=='SSH':
                        set_ssh_enabled(row['username'],True,exp)
                    c.commit()
                    log_event('account_renewed',f'{days} days',row['username'])
                    return send(self,{'ok':True,'action':'renew','id':row['id']})
                if action in ('enable','disable'):
                    enable=action=='enable'
                    if enable:
                        err=account_enable_error(row)
                        if err: raise ValueError(err)
                    if enable:
                        if row['protocol'] in XRAY_TAGS:
                            with XRAY_LOCK:
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
                            set_ssh_enabled(row['username'],True,row['expiry'])
                    else:
                        if row['protocol'] in XRAY_TAGS:
                            del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='Hysteria':
                            kick_hysteria(row['username'])
                        elif row['protocol']=='SSH':
                            set_ssh_enabled(row['username'],False)
                    c.execute('update users set enabled=? where id=?',(1 if enable else 0,row['id']))
                    c.commit()
                    log_event('account_'+action,row['protocol'],row['username'])
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
                elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
                else: del_xray(row['protocol'],row['username'])
                c.execute('delete from users where id=?',(row['id'],)); c.commit()
                log_event('account_deleted',row['protocol'],row['username'])
                return send(self,{'ok':True})
            except Exception as e: c.rollback(); return send(self,{'error':str(e)},500)
            finally: c.close()
        return send(self,{'error':'not found'},404)

if __name__=='__main__':
    conn().close()
    threading.Thread(target=sync_usage,daemon=True).start()
    ThreadingHTTPServer((os.environ.get('PANEL_BIND','0.0.0.0'),PORT),H).serve_forever()
).replace('`','\\`')+'"'
    out=[]; user_done=False; pass_done=False
    for line in lines:
        if line.startswith('ADMIN_USER='):
            out.append('ADMIN_USER='+env_quote(username)); user_done=True
        elif line.startswith('ADMIN_PASSWORD='):
            out.append('ADMIN_PASSWORD='+env_quote(password)); pass_done=True
        else:
            out.append(line)
    if not user_done: out.append('ADMIN_USER='+shlex.quote(username))
    if not pass_done: out.append('ADMIN_PASSWORD='+shlex.quote(password))
    tmp=PANEL_ENV+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: f.write('\n'.join(out)+'\n')
    os.chmod(tmp,0o600)
    os.replace(tmp,PANEL_ENV)
    ADMIN=username
    PASSWORD=password

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

def body(r):
    try:
        length=int(r.headers.get('Content-Length','0') or 0)
    except (TypeError,ValueError):
        raise ValueError('invalid content length')
    if length<0 or length>MAX_REQUEST_BODY:
        raise ValueError('request body too large')
    raw=r.rfile.read(length)
    return json.loads(raw or b'{}')

def public_host():
    return DOMAIN or public_ip()

def public_ip():
    global PUBLIC_IP_CACHE
    if PUBLIC_IP_CACHE: return PUBLIC_IP_CACHE
    try:
        value=subprocess.check_output(['curl','-4fsS','--max-time','3','https://api.ipify.org'],text=True).strip()
        if value:
            PUBLIC_IP_CACHE=value
            return value
    except Exception:
        pass
    return 'SERVER_IP'

def load_xray():
    with open(CFG) as f: return json.load(f)

def save_xray(d):
    with XRAY_LOCK:
        tmp=CFG+'.tmp.json'
        rollback=CFG+'.rollback.tmp'
        try:
            with open(CFG,'rb') as f: previous=f.read()
        except OSError:
            previous=None
        with open(tmp,'w') as f: json.dump(d,f,indent=2)
        test=subprocess.run(['xray','-test','-config',tmp],capture_output=True,text=True)
        if test.returncode:
            try: os.unlink(tmp)
            except OSError: pass
            raise RuntimeError('Xray configuration test failed: '+(test.stderr or test.stdout).strip())
        os.replace(tmp,CFG)
        rr=subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
        if rr.returncode:
            if previous is not None:
                try:
                    with open(rollback,'wb') as f: f.write(previous)
                    os.replace(rollback,CFG)
                    subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
                except Exception:
                    pass
            raise RuntimeError('Xray restart failed: '+(rr.stderr or rr.stdout).strip())

def add_xray(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray()
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            if any(c.get('email')==u for c in clients): raise RuntimeError('Username already exists in Xray')
            client={'email':u,'level':0}
            client['id' if protocol in ('VMess','VLESS') else 'password']=secret
            clients.append(client)
        save_xray(d)

def ensure_xray_client(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        key='id' if protocol in ('VMess','VLESS') else 'password'
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            client=next((x for x in clients if x.get('email')==u),None)
            if client is None:
                clients.append({'email':u,'level':0,key:secret}); changed=True
            elif client.get(key)!=secret:
                client[key]=secret; changed=True
        if changed: save_xray(d)

def del_xray(protocol,u):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib:
                old=len(ib['settings'].get('clients',[]))
                ib['settings']['clients']=[x for x in ib['settings'].get('clients',[]) if x.get('email')!=u]
                changed |= old != len(ib['settings']['clients'])
        if changed: save_xray(d)

def sync_ssh_expiry(u,expiry):
    if expiry:
        exp_date=time.strftime('%Y-%m-%d',time.localtime(int(expiry)+86400))
        subprocess.run(['chage','-E',exp_date,u],check=False)
    else:
        subprocess.run(['chage','-E','-1',u],check=False)

def set_ssh_enabled(u,enabled,expiry=None):
    p=subprocess.run(['usermod','-U' if enabled else '-L',u],capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to change SSH account state')
    if enabled and expiry is not None:
        sync_ssh_expiry(u,expiry)
    elif not enabled:
        subprocess.run(['pkill','-TERM','-u',u],capture_output=True)

def add_ssh(u,password,days):
    if subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError('Linux SSH username already exists')
    subprocess.run(['useradd','-m','-s','/bin/bash',u],check=True)
    p=subprocess.run(['chpasswd'],input=f'{u}:{password}\n',text=True,capture_output=True)
    if p.returncode:
        subprocess.run(['userdel','-r',u],capture_output=True)
        raise RuntimeError('Failed to set SSH password')
    subprocess.run(['usermod','-U',u],capture_output=True,check=False)
    sync_ssh_expiry(u, int(time.time())+days*86400 if days else 0)

def del_ssh(u):
    if subprocess.run(['id',u],capture_output=True).returncode != 0:
        return
    subprocess.run(['pkill','-TERM','-u',u],capture_output=True)
    p=subprocess.run(['userdel','-r',u],capture_output=True,text=True)
    if p.returncode and subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to delete SSH account')

def _xray_usage():
    try:
        p=subprocess.run(['xray','api','statsquery','--server=127.0.0.1:10085'],capture_output=True,text=True,timeout=10)
        if p.returncode != 0: return None
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
        return None

def _hysteria_request(path, method='GET', payload=None):
    if not HY2_STATS_SECRET:
        return None
    try:
        data=None
        headers={'Authorization':HY2_STATS_SECRET}
        if payload is not None:
            data=json.dumps(payload).encode()
            headers['Content-Type']='application/json'
        req=Request(f'http://127.0.0.1:9999{path}',data=data,headers=headers,method=method)
        with urlopen(req,timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None

def kick_hysteria(username):
    return _hysteria_request('/kick','POST',[str(username)]) is not None

def _hysteria_usage():
    data=_hysteria_request('/traffic')
    if data is None: return None
    if not isinstance(data,dict): return {}
    return {str(k): int(v.get('tx',0))+int(v.get('rx',0)) for k,v in data.items() if isinstance(v,dict)}

def _primary_interface():
    try:
        out=subprocess.check_output(['ip','route','show','default'],text=True,timeout=3)
        parts=out.split()
        return parts[parts.index('dev')+1] if 'dev' in parts else ''
    except Exception:
        return ''

def _server_bytes():
    iface=_primary_interface()
    if not iface: return 0,0
    try:
        with open(f'/sys/class/net/{iface}/statistics/rx_bytes') as f: rx=int(f.read().strip())
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes') as f: tx=int(f.read().strip())
        return rx,tx
    except Exception:
        return 0,0

def _human_bytes(n):
    n=float(max(int(n or 0),0))
    units=('B','KB','MB','GB','TB','PB')
    for u in units:
        if n < 1024 or u==units[-1]:
            return f'{n:.2f} {u}'
        n/=1024
    return '0.00 B'

def log_event(action, details='', username=''):
    try:
        c=conn()
        c.execute('insert into events(created_at,action,username,details) values(?,?,?,?)',
                  (int(time.time()),str(action),str(username),str(details)))
        c.execute('delete from events where id not in (select id from events order by id desc limit 500)')
        c.commit(); c.close()
    except Exception:
        pass

def _network_rate():
    iface=_primary_interface()
    if not iface:
        return {'rx_bytes':0,'tx_bytes':0,'rx_bps':0,'tx_bps':0}
    try:
        with open(f'/sys/class/net/{iface}/statistics/rx_bytes') as f: rx=int(f.read())
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes') as f: tx=int(f.read())
        now=time.time()
        prev=getattr(_network_rate,'prev',None)
        _network_rate.prev=(now,rx,tx)
        if not prev:
            return {'rx_bytes':rx,'tx_bytes':tx,'rx_bps':0,'tx_bps':0}
        dt=max(now-prev[0],0.1)
        return {'rx_bytes':rx,'tx_bytes':tx,'rx_bps':max(rx-prev[1],0)/dt,'tx_bps':max(tx-prev[2],0)/dt}
    except Exception:
        return {'rx_bytes':0,'tx_bytes':0,'rx_bps':0,'tx_bps':0}

def _system_metrics():
    try:
        load=os.getloadavg()
    except Exception:
        load=(0,0,0)
    mem={}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k,v=line.split(':',1)
                mem[k]=int(v.strip().split()[0])*1024
    except Exception:
        pass
    total=mem.get('MemTotal',0); available=mem.get('MemAvailable',0)
    used=max(total-available,0)
    du=__import__('shutil').disk_usage('/')
    net=_network_rate()
    return {
        'timestamp':int(time.time()),
        'cpu_load':[round(float(x),2) for x in load],
        'cpu_count':os.cpu_count() or 1,
        'memory':{'total':total,'used':used,'available':available},
        'disk':{'total':du.total,'used':du.used,'free':du.free},
        'network':net,
        'uptime_seconds':int(time.time()-__import__('psutil').boot_time()) if __import__('importlib').util.find_spec('psutil') else 0
    }

def _active_sessions():
    out=[]
    try:
        p=subprocess.run(['ss','-Hntp','state','established'],capture_output=True,text=True,timeout=5)
        for line in p.stdout.splitlines():
            parts=line.split()
            if len(parts)<5: continue
            local=parts[2]; peer=parts[3]
            proc=''
            pid=None
            m=re.search(r'users:\(\("([^"]+)",pid=(\d+)',line)
            if m:
                proc=m.group(1); pid=int(m.group(2))
            user=''
            if pid:
                try: user=subprocess.check_output(['ps','-o','user=','-p',str(pid)],text=True).strip()
                except Exception: pass
            out.append({'local':local,'remote':peer,'process':proc,'pid':pid,'user':user})
            if len(out)>=100: break
    except Exception:
        pass
    return out

def _certificate_info():
    path='/etc/unified-vps/xray.crt'
    if not os.path.exists(path): return {'ok':False,'error':'Certificate not found'}
    try:
        p=subprocess.run(['openssl','x509','-in',path,'-noout','-subject','-issuer','-startdate','-enddate'],
                         capture_output=True,text=True,timeout=5)
        vals={}
        for line in p.stdout.splitlines():
            if '=' in line:
                k,v=line.split('=',1); vals[k.strip()]=v.strip()
        end=vals.get('notAfter','')
        epoch=0
        if end:
            epoch=int(time.mktime(time.strptime(end,'%b %d %H:%M:%S %Y %Z')))
        days=int((epoch-time.time())/86400) if epoch else -1
        return {'ok':p.returncode==0,'subject':vals.get('subject',''),'issuer':vals.get('issuer',''),
                'start':vals.get('notBefore',''),'expiry':end,'days_remaining':days}
    except Exception as e:
        return {'ok':False,'error':str(e)}

def _security_info():
    failed=0
    try:
        text=subprocess.check_output(['journalctl','-u','ssh','--since','24 hours ago','--no-pager'],text=True,stderr=subprocess.DEVNULL)
        failed=sum(1 for x in text.splitlines() if 'Failed password' in x or 'Invalid user' in x)
    except Exception: pass
    banned=0; f2b='inactive'
    try:
        f2b=service_state('fail2ban')
        text=subprocess.check_output(['fail2ban-client','status','sshd'],text=True,stderr=subprocess.DEVNULL)
        m=re.search(r'Currently banned:\s*(\d+)',text); banned=int(m.group(1)) if m else 0
    except Exception: pass
    try:
        fw=sum(1 for x in subprocess.check_output(['iptables','-S','INPUT'],text=True,stderr=subprocess.DEVNULL).splitlines() if x.strip())
    except Exception: fw=0
    try:
        ssh_cfg=subprocess.check_output(['sshd','-T'],text=True,stderr=subprocess.DEVNULL)
        auth_cfg={k:v for k,v in (line.split(None,1) for line in ssh_cfg.splitlines() if line.split(None,1)[0] in ('passwordauthentication','kbdinteractiveauthentication','usepam'))}
    except Exception: auth_cfg={}
    return {'fail2ban':f2b,'banned':banned,'failed_ssh_24h':failed,'firewall_rules':fw,'ssh_auth':auth_cfg}

def sync_usage():
    while True:
        try:
            xusage=_xray_usage()
            husage=_hysteria_usage()
            c=conn()
            rows=c.execute('select * from users').fetchall()
            now=int(time.time())
            today=time.strftime('%Y-%m-%d',time.localtime(now))
            disable=[]
            for row in rows:
                if row['protocol'] in XRAY_TAGS:
                    if xusage is None: continue
                    raw=xusage.get(row['username'],0)
                elif row['protocol']=='Hysteria':
                    if husage is None: continue
                    raw=husage.get(row['username'],0)
                else:
                    raw=0
                prev=int(row['raw_bytes'] or 0)
                delta=raw-prev if raw >= prev else raw
                used=int(row['used_bytes'] or 0)+delta
                daily=int(row['daily_used_bytes'] or 0)
                usage_day=row['usage_day'] or ''
                if usage_day != today:
                    daily=0
                daily += delta
                expired=bool(row['expiry'] and row['expiry']<=now)
                quota_hit=bool(row['quota_bytes'] and used>=row['quota_bytes'])
                if row['enabled'] and (expired or quota_hit):
                    disable.append(row)
                c.execute('update users set used_bytes=?,raw_bytes=?,daily_used_bytes=?,usage_day=? where id=?',
                          (used,raw,daily,today,row['id']))

            rx,tx=_server_bytes()
            srv=c.execute('select * from server_usage where id=1').fetchone()
            if srv:
                raw_rx=int(srv['raw_rx'] or 0); raw_tx=int(srv['raw_tx'] or 0)
                server_delta=(rx-raw_rx if rx >= raw_rx else rx)+(tx-raw_tx if tx >= raw_tx else tx)
                server_all=int(srv['all_time_bytes'] or 0)+server_delta
                server_daily=int(srv['daily_bytes'] or 0)
                if (srv['usage_day'] or '') != today:
                    server_daily=0
                server_daily += server_delta
                c.execute('update server_usage set raw_rx=?,raw_tx=?,all_time_bytes=?,daily_bytes=?,usage_day=? where id=1',
                          (rx,tx,server_all,server_daily,today))
                c.execute('insert into usage_daily(day,bytes) values(?,?) on conflict(day) do update set bytes=excluded.bytes',
                          (today,server_daily))
            c.commit(); c.close()

            xrows=[r for r in disable if r['protocol'] in XRAY_TAGS]
            if xrows:
                with XRAY_LOCK:
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
                log_event('account_auto_disabled','expired or quota reached',row['username'])
                if row['protocol']=='Hysteria':
                    kick_hysteria(row['username'])
                if row['protocol']=='SSH':
                    try: set_ssh_enabled(row['username'],False)
                    except Exception: pass
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
    except (TypeError,ValueError): raise ValueError('quota must be a finite non-negative number')
    if not math.isfinite(quota_gb) or quota_gb < 0: raise ValueError('quota must be a finite non-negative number')
    q=int(quota_gb*(1024**3))
    try: days=int(d.get('days',0) or 0)
    except (TypeError,ValueError): raise ValueError('days must be a whole number')
    if days < 0: raise ValueError('days cannot be negative')
    if days > 36500: raise ValueError('days exceeds maximum supported duration')
    if p not in XRAY_TAGS and p not in ('Hysteria','SSH'): raise ValueError('invalid protocol')
    # SSH quota accounting is not currently supported, but accept the field
    # from CLI clients for compatibility and keep the stored quota at zero.
    if p=='SSH':
        q=0
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',u): raise ValueError('invalid username')
    secret=str(d.get('secret') or (str(uuid.uuid4()) if p in ('VLESS','VMess') else secrets.token_urlsafe(18)))
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
        if p=='SSH':
            add_ssh(u,secret,days)
            ssh_created=True
        elif p!='Hysteria':
            add_xray(p,u,secret)
            xray_created=True
        c.execute('insert into users(username,protocol,secret,quota_bytes,expiry,created_at) values(?,?,?,?,?,?)',(u,p,secret,q,exp,int(time.time())))
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

def account_enable_error(row):
    now=int(time.time())
    if row['expiry'] and row['expiry']<=now:
        return 'account has expired; renew it before enabling'
    if row['quota_bytes'] and int(row['used_bytes'] or 0)>=int(row['quota_bytes']):
        return 'account quota has been reached; renew it before enabling'
    return None

def service_state(name):
    try:
        return subprocess.check_output(['systemctl','is-active',name],stderr=subprocess.DEVNULL,text=True).strip()
    except Exception:
        return 'unknown'

class H(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def do_GET(self):
        if self.path=='/health': return send(self,{'ok':True})
        if self.path in ('/','/setup') and not admin_configured(): return _setup_page(self)
        if self.path=='/setup':
            self.send_response(404); self.end_headers(); return
        if not auth(self.headers):
            self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return
        if self.path=='/api/backup':
            files=[]
            for path in sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)[:10]:
                try:
                    files.append({'name':os.path.basename(path),'size':os.path.getsize(path),'created_at':int(os.path.getmtime(path))})
                except OSError: pass
            return send(self,{'backups':files})

        if self.path=='/api/users':
            c=conn(); rows=[record(x) for x in c.execute('select * from users order by id desc')]; c.close()
            now=int(time.time())
            for x in rows:
                x['days_remaining']=None if not x['expiry'] else max(int((x['expiry']-now)/86400),0)
                x['expiry_warning']=bool(x['expiry'] and x['expiry']<=now+7*86400)
            return send(self,rows)
        if self.path=='/api/usage-history':
            c=conn()
            rows=c.execute('select day,bytes from usage_daily order by day desc limit 30').fetchall()
            c.close()
            rows=list(reversed(rows))
            return send(self,{'values':[int(x['bytes'] or 0) for x in rows],'days':[x['day'] for x in rows]})

        if self.path=='/api/usage':
            c=conn()
            rows=c.execute('select id,username,protocol,used_bytes,daily_used_bytes,quota_bytes,usage_day from users order by id desc').fetchall()
            srv=c.execute('select * from server_usage where id=1').fetchone()
            c.close()
            data={
                'updated_at':int(time.time()),
                'server':{
                    'daily_bytes':int(srv['daily_bytes'] if srv else 0),
                    'all_time_bytes':int(srv['all_time_bytes'] if srv else 0),
                },
                'ssh_per_user_metered':False,
                'accounts':[
                    {
                        'id':int(r['id']),
                        'username':r['username'],
                        'protocol':r['protocol'],
                        'daily_bytes':int(r['daily_used_bytes'] or 0),
                        'all_time_bytes':int(r['used_bytes'] or 0),
                        'quota_bytes':int(r['quota_bytes'] or 0),
                        'usage_day':r['usage_day'] or ''
                    } for r in rows
                ]
            }
            return send(self,data)
        if self.path=='/api/metrics':
            return send(self,_system_metrics())

        if self.path=='/api/sessions':
            return send(self,{'updated_at':int(time.time()),'sessions':_active_sessions()})

        if self.path=='/api/security':
            return send(self,_security_info())

        if self.path=='/api/certificate':
            return send(self,_certificate_info())

        if self.path=='/api/events':
            c=conn()
            rows=c.execute('select id,created_at,action,username,details from events order by id desc limit 100').fetchall()
            c.close()
            return send(self,{'events':[dict(x) for x in rows]})

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
            counts={p:sum(1 for x in rows if x['protocol']==p) for p in ('SSH','VLESS','VMess','Trojan','Hysteria')}
            active=sum(1 for x in rows if x['enabled'])
            total_used=sum(int(x['used_bytes'] or 0) for x in rows)
            total_daily=sum(int(x['daily_used_bytes'] or 0) for x in rows)
            usage_conn=conn()
            srv_row=usage_conn.execute('select * from server_usage where id=1').fetchone()
            server_daily=int(srv_row['daily_bytes'] if srv_row else 0)
            server_all=int(srv_row['all_time_bytes'] if srv_row else 0)
            usage_conn.close()
            services={
                'SSH':service_state('ssh'),
                'NGINX':service_state('nginx'),
                'HAProxy':service_state('haproxy'),
                'Xray':service_state('xray'),
                'Hysteria 2':service_state('hysteria-server'),
                'Panel':service_state('unified-vps-panel')
            }
            reboot='04:00 local' if os.path.exists('/etc/cron.d/unified-vps-daily-reboot') else 'Not configured'

            def state_badge(state):
                cls='up' if state=='active' else 'down'
                return f'<span class="status {cls}"><span class="dot"></span>{html.escape(state.upper())}</span>'

            rows_html=[]
            for x in rows:
                xid=x['id']; protocol=x['protocol']; username=html.escape(x['username'],quote=True)
                secret=html.escape(str(x['secret']),quote=True)
                enabled=bool(x['enabled'])
                enabled_label='Enabled' if enabled else 'Disabled'
                action='disable' if enabled else 'enable'
                action_label='Disable' if enabled else 'Enable'
                expiry='Unlimited' if not x['expiry'] else time.strftime('%Y-%m-%d %H:%M',time.localtime(x['expiry']))
                used=f"{x['used_bytes']/(1024**3):.2f} GB"
                daily=f"{x['daily_used_bytes']/(1024**3):.2f} GB"
                quota='Unlimited' if not x['quota_bytes'] else f"{x['quota_bytes']/(1024**3):.2f} GB"
                usage_text = "Not metered" if protocol=='SSH' else used
                daily_text = "Today: not metered" if protocol=='SSH' else f"Today: {daily}"
                if protocol in XRAY_TAGS:
                    uris=[]
                    for port in ('80','443'):
                        uri=html.escape(x['uris'].get(port,''),quote=True)
                        uris.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy {port}</button></div>')
                    connection='<div class="uri-stack">'+''.join(uris)+'</div>'
                elif protocol=='SSH':
                    parts=[]
                    for label,key in (('WS 80','WebSocket'),('WS 8080','WebSocket8080'),('WS 8880','WebSocket8880'),('WSS 443','WebSocketTLS'),('WSS 8443','WebSocketTLS8443')):
                        uri=html.escape(x['uris'].get(key,''),quote=True)
                        parts.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy</button></div>')
                    connection=f'<div class="sshmeta"><span>Host: {html.escape(x["host"],quote=True)}</span><span>Path: {html.escape(x["uris"].get("Path","/ssh"),quote=True)}</span></div><div class="uri-stack">{"".join(parts)}</div>'
                else:
                    uri=html.escape(next(iter(x['uris'].values()),''),quote=True)
                    connection=f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy URI</button></div>'
                rows_html.append(
                    f'<tr data-row data-id="{xid}" data-user="{username}" data-protocol="{html.escape(protocol.lower())}">'
                    f'<td><input class="rowcheck" type="checkbox" value="{xid}"></td><td><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{username}</strong><span class="muted">{html.escape(protocol)}</span></div></div></td>'
                    f'<td>{state_badge("active" if enabled else "disabled")}</td>'
                    f'<td><span class="pill">{html.escape(str(x["port"]))}</span></td>'
                    f'<td><button class="secret-btn" data-secret="{secret}" type="button">Reveal</button></td>'
                    f'<td><span id="alltime-{xid}">{usage_text}</span><span class="muted"> / {quota}</span><span id="daily-{xid}" class="muted">{daily_text}</span></td>'
                    f'<td><span class="muted {"warn" if x["expiry"] and x["expiry"]<=time.time()+7*86400 else ""}">{html.escape(expiry)}</span>{("<span class=\"muted warn\">Expires soon</span>" if x["expiry"] and x["expiry"]<=time.time()+7*86400 else "")}</td>'
                    f'<td>{connection}</td>'
                    f'<td><div class="actions"><button class="ghost" data-action="{action}" data-id="{xid}" type="button">{action_label}</button><button class="ghost" data-renew="{xid}" type="button">Renew</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div></td>'
                    f'</tr>'
                )

            rows_html=''.join(rows_html) or '<tr><td colspan="9"><div class="empty">No accounts yet. Create the first account above.</div></td></tr>'
            cards_html=[]
            for x in rows:
                xid=x['id']; protocol=x['protocol']; enabled=bool(x['enabled'])
                expiry='Unlimited' if not x['expiry'] else time.strftime('%Y-%m-%d',time.localtime(x['expiry']))
                usage='Not metered' if protocol=='SSH' else _human_bytes(x['used_bytes'])
                today='Not metered' if protocol=='SSH' else _human_bytes(x['daily_used_bytes'])
                expiry_warn=bool(x['expiry'] and x['expiry']<=time.time()+7*86400)
                cards_html.append(
                    f'<article class="account-card" data-card-user="{html.escape(x["username"],quote=True)}" data-card-protocol="{html.escape(protocol.lower())}">'
                    f'<div class="cardtop"><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{html.escape(x["username"])}</strong><span class="muted">{html.escape(protocol)}</span></div></div>{state_badge("active" if enabled else "disabled")}</div>'
                    f'<div class="cardstats"><div><span>Today</span><strong>{today}</strong></div><div><span>All time</span><strong>{usage}</strong></div><div><span>Expiry</span><strong class="{"warn" if expiry_warn else ""}">{html.escape(expiry)}</strong></div></div>'
                    f'<div class="cardactions"><button class="ghost" data-action="{"disable" if enabled else "enable"}" data-id="{xid}" type="button">{"Disable" if enabled else "Enable"}</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div>'
                    f'</article>'
                )
            cards_html=''.join(cards_html) or '<div class="empty">No accounts yet.</div>'
            service_html=''.join(f'<div class="service-card"><span>{html.escape(k)}</span>{state_badge(v)}</div>' for k,v in services.items())

            page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#06110b">
<title>Unified VPS — Control Center</title>
<style>
:root{--bg:#06110b;--panel:#0b1811;--panel2:#0e2116;--line:#173524;--text:#ecfff2;--muted:#87a995;--accent:#42f58d;--accent2:#14c96b;--danger:#ff6b78;--shadow:0 24px 70px rgba(0,0,0,.38)}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 500px at 80% -10%,rgba(66,245,141,.09),transparent 60%),radial-gradient(700px 400px at 5% 0,rgba(20,201,107,.07),transparent 60%),var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button{cursor:pointer}
.app{min-height:100vh;display:grid;grid-template-columns:240px 1fr}
.sidebar{position:sticky;top:0;height:100vh;padding:24px 16px;border-right:1px solid var(--line);background:rgba(4,13,8,.78);backdrop-filter:blur(18px)}
.brand{display:flex;gap:12px;align-items:center;padding:8px 10px 24px}.brandmark{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#42f58d,#0d7f45);color:#031108;font-weight:900;box-shadow:0 10px 28px rgba(66,245,141,.18)}.brand h1{font-size:14px;margin:0}.brand p{margin:2px 0 0;color:var(--muted);font-size:11px}
.nav{display:grid;gap:6px}.nav a{padding:11px 12px;border-radius:10px;color:#a9c5b2;text-decoration:none}.nav a.active,.nav a:hover{background:rgba(66,245,141,.08);color:var(--text)}
.sidefoot{position:absolute;bottom:20px;left:16px;right:16px;padding:12px;border:1px solid var(--line);border-radius:12px;background:rgba(13,33,22,.55)}.sidefoot .label{font-size:11px;color:var(--muted)}.sidefoot strong{display:block;margin-top:3px;font-size:13px}
.main{min-width:0}.topbar{height:72px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;border-bottom:1px solid var(--line);background:rgba(6,17,11,.58);backdrop-filter:blur(18px);position:sticky;top:0;z-index:10}.topbar h2{margin:0;font-size:18px}.topbar p{margin:2px 0 0;color:var(--muted);font-size:12px}.top-actions{display:flex;align-items:center;gap:10px}.badge{padding:7px 10px;border:1px solid var(--line);background:rgba(255,255,255,.02);border-radius:999px;color:var(--muted);font-size:11px}
.content{padding:26px;max-width:1500px;margin:auto}.hero{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:20px}.hero h3{font-size:28px;margin:0}.hero p{margin:5px 0 0;color:var(--muted)}.primary{border:0;border-radius:11px;padding:11px 15px;background:linear-gradient(135deg,var(--accent),#1dbb68);color:#03200f;font-weight:800;box-shadow:0 12px 32px rgba(66,245,141,.16)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.stat,.panel{border:1px solid var(--line);background:linear-gradient(180deg,rgba(14,33,22,.9),rgba(8,20,13,.9));border-radius:16px;box-shadow:var(--shadow)}.stat{padding:16px}.stat .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.stat .v{font-size:28px;font-weight:800;margin-top:6px}.stat .s{color:#a6c3b0;font-size:11px;margin-top:4px}
.grid2{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;margin-top:14px}.panel{padding:18px}.panelhead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}.panelhead h4{margin:0;font-size:14px}.panelhead p{margin:3px 0 0;color:var(--muted);font-size:11px}
.services{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.service-card{display:flex;align-items:center;justify-content:space-between;padding:11px 12px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.02)}.status{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:5px 8px;font-size:10px;font-weight:800;letter-spacing:.06em}.status.up{background:rgba(66,245,141,.08);color:var(--accent)}.status.down{background:rgba(255,107,120,.08);color:var(--danger)}.dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 12px currentColor}
.matrix{display:grid;gap:8px}.matrix div{display:flex;justify-content:space-between;padding:10px 12px;border:1px solid var(--line);border-radius:10px}.matrix span:last-child{color:var(--accent);font-weight:700}
.accounts{margin-top:14px}.toolbar{display:flex;gap:10px;flex-wrap:wrap}.search{min-width:240px;flex:1;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:#08140c;color:var(--text);outline:none}.select{padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:#08140c;color:var(--text)}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:1080px}th,td{padding:12px 13px;text-align:left;border-bottom:1px solid rgba(23,53,36,.72);vertical-align:top}th{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;background:#09170f}tr:last-child td{border-bottom:0}
.usercell{display:flex;align-items:center;gap:9px}.avatar{width:31px;height:31px;border-radius:9px;display:grid;place-items:center;background:rgba(66,245,141,.1);color:var(--accent);font-weight:800}.usercell strong{display:block}.muted{display:block;color:var(--muted);font-size:11px}.pill{display:inline-block;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.04);font-size:10px;color:#bcd4c4}
.copyline{display:flex;align-items:center;gap:7px;margin:5px 0;max-width:480px}.copyline code{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;padding:7px 9px;border:1px solid var(--line);border-radius:8px;background:#06100a;color:#bdeccf;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.copy-btn,.ghost,.danger,.secret-btn{border:1px solid var(--line);border-radius:8px;padding:7px 9px;background:#0a170f;color:#bfe4ca;font-size:11px}.copy-btn:hover,.ghost:hover,.secret-btn:hover{border-color:#2e754c;color:var(--text)}.danger{color:#ff9da6;border-color:rgba(255,107,120,.24)}.danger:hover{background:rgba(255,107,120,.08)}.actions{display:flex;gap:6px;flex-wrap:wrap}.sshmeta{display:flex;gap:10px;flex-wrap:wrap;color:var(--muted);font-size:11px}.empty{text-align:center;color:var(--muted);padding:30px}
.overlay{position:fixed;inset:0;background:rgba(1,7,4,.72);backdrop-filter:blur(10px);display:none;align-items:center;justify-content:center;padding:20px;z-index:30}.overlay.open{display:flex}.modal{width:min(560px,100%);background:#09170f;border:1px solid var(--line);border-radius:18px;box-shadow:0 30px 90px rgba(0,0,0,.5);padding:20px}.modalhead{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px}.modalhead h3{margin:0}.modalhead p{margin:4px 0;color:var(--muted);font-size:12px}.close{border:1px solid var(--line);background:#07110b;color:#b4c9bc;border-radius:8px;padding:6px 9px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{display:grid;gap:6px}.field.full{grid-column:1/-1}.field label{font-size:11px;color:var(--muted)}.field input,.field select{padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#06100a;color:var(--text);outline:none}.modalfoot{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}.secondary{border:1px solid var(--line);background:#08140c;color:#b9d0c2;border-radius:10px;padding:10px 13px}
.toast{position:fixed;right:20px;bottom:20px;z-index:50;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:#0c1d13;color:var(--text);box-shadow:var(--shadow);display:none}.toast.show{display:block}.account-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:14px}.account-card{border:1px solid var(--line);border-radius:14px;padding:14px;background:linear-gradient(180deg,rgba(15,36,24,.78),rgba(7,18,12,.78))}.cardtop{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.cardstats{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin:13px 0}.cardstats div{padding:8px;border-radius:9px;background:rgba(255,255,255,.025);border:1px solid var(--line)}.cardstats span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase}.cardstats strong{display:block;margin-top:3px;font-size:11px}.cardactions{display:flex;gap:7px}.account-card .danger{margin-left:auto}.eventlist{display:grid;gap:7px;max-height:260px;overflow:auto}.event{padding:9px 10px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.02)}.event strong{font-size:11px}.event small{display:block;color:var(--muted);margin-top:2px}.warn{color:#ffd166!important}.dangertext{color:var(--danger)!important}.metric-good{color:var(--accent)!important}
@media(max-width:1050px){.app{grid-template-columns:1fr}.sidebar{display:none}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}.account-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar{padding:0 16px}.content{padding:18px}}
@media(max-width:620px){.stats{grid-template-columns:1fr}.account-cards{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero h3{font-size:23px}.formgrid{grid-template-columns:1fr}.field.full{grid-column:auto}.top-actions .badge{display:none}}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand"><div class="brandmark">UV</div><div><h1>Unified VPS</h1><p>Control Center</p></div></div>
  <nav class="nav">
    <a class="active" href="#dashboard">Dashboard</a>
    <a href="#accounts">Accounts</a>
    <a href="#transports">Transports</a>
    <a href="#services">Services</a>
  </nav>
  <div class="sidefoot"><span class="label">DAILY REBOOT</span><strong>__REBOOT__</strong><span class="label">Panel access: __PANEL_URL__</span></div>
</aside>
<main class="main">
  <header class="topbar"><div><h2>Command Center</h2><p>__DOMAIN__</p></div><div class="top-actions"><span class="badge">IPv4 __IP__</span><span class="badge">__OS__</span></div></header>
  <section class="content" id="dashboard">
    <div class="hero"><div><h3>Server overview</h3><p>Live account inventory, services and transport endpoints.</p><span id="usageStamp" class="muted" style="margin-top:6px">Usage updating…</span></div><button class="primary" id="openCreate" type="button">+ Create account</button></div>
    <div class="stats">
      <div class="stat"><div class="k">Total accounts</div><div class="v">__TOTAL__</div><div class="s">All protocols</div></div>
      <div class="stat"><div class="k">Active accounts</div><div class="v">__ACTIVE__</div><div class="s">Currently enabled</div></div>
      <div class="stat"><div class="k">Server traffic today</div><div class="v" id="serverDaily">__SERVER_DAILY__</div><div class="s">Live interface accounting</div></div>
      <div class="stat"><div class="k">Server traffic all time</div><div class="v" id="serverAll">__SERVER_ALL__</div><div class="s">Persistent total</div></div>
      <div class="stat"><div class="k">Daily reboot</div><div class="v" style="font-size:20px">__REBOOT__</div><div class="s">Automatic maintenance</div></div>
      <div class="stat"><div class="k">CPU load</div><div class="v" id="cpuLoad">—</div><div class="s">Live 10s telemetry</div></div>
      <div class="stat"><div class="k">Memory</div><div class="v" id="memUse">—</div><div class="s">Used / total</div></div>
      <div class="stat"><div class="k">Disk</div><div class="v" id="diskUse">—</div><div class="s">Used / total</div></div>
    </div>
    <div class="grid2" id="services">
      <section class="panel"><div class="panelhead"><div><h4>Service health</h4><p>Critical components detected by systemd.</p></div></div><div class="services">__SERVICES__</div></section>
      <section class="panel" id="transports"><div class="panelhead"><div><h4>Transport matrix</h4><p>Public listeners exposed by Unified VPS.</p></div></div>
        <div class="matrix">
          <div><span>SSH over WebSocket</span><span>80 / 8080 / 8880</span></div>
          <div><span>SSH over WSS</span><span>443 / 8443</span></div>
          <div><span>SSH raw TCP</span><span>143 / 8080 / 8443</span></div>
          <div><span>VLESS / VMess / Trojan</span><span>80 / 443</span></div>
          <div><span>Hysteria 2</span><span>UDP 53</span></div>
          <div><span>Web panel</span><span>TCP 6080</span></div>
        </div>
      </section>
    </div>
    <div class="grid2">
      <section class="panel">
        <div class="panelhead"><div><h4>Live network</h4><p>Interface throughput and active TCP sessions.</p></div></div>
        <div class="matrix">
          <div><span>Download / RX</span><span id="rxRate">—</span></div>
          <div><span>Upload / TX</span><span id="txRate">—</span></div>
          <div><span>Active sessions</span><span id="sessionCount">—</span></div>
          <div><span>Certificate</span><span id="certState">Checking…</span></div>
          <div><span>Fail2Ban</span><span id="f2bState">Checking…</span></div>
        </div>
      </section>
      <section class="panel">
        <div class="panelhead"><div><h4>System activity</h4><p>Recent account and maintenance events.</p></div></div>
        <div id="events" class="eventlist"><div class="muted">Loading events…</div></div>
      </section>
    </div>
    <section class="panel" id="sessionsPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Active connections</h4><p>Current established TCP sessions visible to the server.</p></div><button class="secondary" id="refreshSessions" type="button">Refresh</button></div>
      <div class="tablewrap"><table style="min-width:760px"><thead><tr><th>Process</th><th>User</th><th>Local</th><th>Remote</th><th>PID</th></tr></thead><tbody id="sessionsBody"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></div>
    </section>
    <section class="panel" id="securityPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Security center</h4><p>SSH protection, firewall and certificate posture.</p></div></div>
      <div class="services" id="securityGrid"><div class="service-card">Loading…</div></div>
    </section>
    <section class="panel" id="activityPanel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Usage history</h4><p>Server traffic is persisted daily and all-time.</p></div></div>
      <canvas id="usageChart" height="120" style="width:100%;display:block"></canvas>
    </section>
    <section class="panel" style="margin-top:14px">
      <div class="panelhead"><div><h4>Account expiry</h4><p>Accounts expiring within the next seven days.</p></div></div>
      <div id="expiryList" class="services"><div class="muted">Checking expiries…</div></div>
    </section>
    <section class="panel accounts" id="accounts">
      <div class="panelhead"><div><h4>Account management</h4><p>Create, renew, enable, disable and copy connection credentials.</p></div>
        <div class="toolbar"><input class="search" id="search" placeholder="Search username or protocol…"><select class="select" id="filter"><option value="">All protocols</option><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select><button class="secondary" id="bulkEnable" type="button">Enable selected</button><button class="secondary" id="bulkDisable" type="button">Disable selected</button><button class="danger" id="bulkDelete" type="button">Delete selected</button><button class="secondary" id="backupNow" type="button">Backup</button><button class="secondary" id="restoreLatest" type="button">Restore latest</button><button class="secondary" id="renewCert" type="button">Renew certificate</button><button class="secondary" id="speedtest" type="button">Run speedtest</button></div>
      </div>
      <pre id="speedout" style="display:none;max-height:260px;overflow:auto;padding:12px;border:1px solid var(--line);border-radius:10px;background:#06100a;color:#bcebcf;font-size:11px"></pre>
      <div class="account-cards" id="accountCards">__ACCOUNT_CARDS__</div>
      <div class="tablewrap"><table><thead><tr><th><input id="selectAll" type="checkbox" title="Select all"></th><th>Account</th><th>Status</th><th>Ports</th><th>Secret</th><th>Usage</th><th>Expiry</th><th>Connection URI</th><th>Actions</th></tr></thead><tbody id="accountsBody">__ROWS__</tbody></table></div>
    </section>
  </section>
</main>
</div>

<div class="overlay" id="modal">
  <div class="modal">
    <div class="modalhead"><div><h3>Create account</h3><p>Provision a new Unified VPS identity.</p></div><button class="close" id="closeCreate" type="button">Close</button></div>
    <form id="createForm">
      <div class="formgrid">
        <div class="field"><label>Username</label><input name="username" required maxlength="32"></div>
        <div class="field"><label>Protocol</label><select name="protocol" id="protocol"><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select></div>
        <div class="field full" id="sshSecretField"><label>SSH password</label><input name="secret" id="sshSecret" type="password" autocomplete="new-password"></div>
        <div class="field"><label>Duration (days)</label><input name="days" type="number" min="0" value="0"></div>
        <div class="field"><label>Quota (GB)</label><input name="quota_gb" id="quota" type="number" min="0" step="0.1" value="0"></div>
      </div>
      <div class="modalfoot"><button class="secondary" id="cancelCreate" type="button">Cancel</button><button class="primary" type="submit">Create account</button></div>
    </form>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const $=s=>document.querySelector(s);
function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2200)}
async function copyText(value,button){
  let ok=false;
  try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(value);ok=true}}catch(e){}
  if(!ok){
    const ta=document.createElement("textarea");ta.value=value;ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);ta.focus();ta.select();
    try{ok=document.execCommand("copy")}catch(e){ok=false}ta.remove();
  }
  if(ok){const old=button.textContent;button.textContent="Copied";setTimeout(()=>button.textContent=old,1200)}else{toast("Copy blocked — URI selected for manual copy.")}
}
document.addEventListener("click",async e=>{
  const copy=e.target.closest("[data-copy]"); if(copy){await copyText(copy.dataset.copy,copy);return}
  const reveal=e.target.closest(".secret-btn"); if(reveal){if(reveal.dataset.revealed==="1"){reveal.textContent="Reveal";reveal.dataset.revealed="0"}else{reveal.textContent=reveal.dataset.secret;reveal.dataset.revealed="1"}return}
  const act=e.target.closest("[data-action]"); if(act){
    const id=act.dataset.id, action=act.dataset.action;
    const r=await fetch("/api/users/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(id),action:action})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Action failed");return} location.reload(); return
  }
  const del=e.target.closest("[data-delete]"); if(del){
    if(!confirm("Delete this account permanently?")) return;
    const r=await fetch("/api/users/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(del.dataset.delete)})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Delete failed");return} location.reload(); return
  }
  const renew=e.target.closest("[data-renew]"); if(renew){
    const days=prompt("Renew for how many days?","30"); if(!days||!/^\\d+$/.test(days)||Number(days)<1)return;
    const r=await fetch("/api/users/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(renew.dataset.renew),action:"renew",days:Number(days)})});
    const j=await r.json(); if(!r.ok){toast(j.error||"Renewal failed");return} location.reload(); return
  }
});
$("#openCreate").onclick=()=>$("#modal").classList.add("open");
$("#closeCreate").onclick=$("#cancelCreate").onclick=()=>$("#modal").classList.remove("open");
const protocol=$("#protocol"), sshField=$("#sshSecretField"), sshSecret=$("#sshSecret"), quota=$("#quota");
function updateFields(){const ssh=protocol.value==="SSH";sshField.style.display=ssh?"grid":"none";sshSecret.required=ssh;quota.disabled=ssh;if(ssh)quota.value="0"}
protocol.onchange=updateFields;updateFields();
$("#createForm").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.target), payload=Object.fromEntries(f.entries());
  payload.days=Number(payload.days||0);payload.quota_gb=Number(payload.quota_gb||0);
  const r=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const j=await r.json(); if(!r.ok){toast(j.error||"Account creation failed");return} location.reload();
};
$("#search").oninput=$("#filter").onchange=()=>{
  const q=$("#search").value.toLowerCase(), p=$("#filter").value.toLowerCase();
  document.querySelectorAll("[data-row]").forEach(r=>{const hit=(!q||(r.dataset.user||"").includes(q)||(r.dataset.protocol||"").includes(q))&&(!p||(r.dataset.protocol||"")===p);r.style.display=hit?"":"none"});
  document.querySelectorAll("[data-card-user]").forEach(r=>{const hit=(!q||(r.dataset.cardUser||"").includes(q)||(r.dataset.cardProtocol||"").includes(q))&&(!p||(r.dataset.cardProtocol||"")===p);r.style.display=hit?"":"none"});
};
async function selectedIds(){return [...document.querySelectorAll(".rowcheck:checked")].map(x=>Number(x.value)).filter(Boolean)}
async function bulk(action){
  const ids=await selectedIds(); if(!ids.length){toast("Select at least one account");return}
  let days=0;if(action==="renew"){days=Number(prompt("Renew selected accounts for how many days?","30")||0);if(!days)return}
  if(action==="delete"&&!confirm("Delete "+ids.length+" selected accounts permanently?"))return;
  const r=await fetch("/api/users/bulk",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids,action,days})});
  const j=await r.json();if(!r.ok){toast(j.error||"Bulk action failed");return}location.reload();
}
$("#selectAll").onchange=e=>document.querySelectorAll(".rowcheck").forEach(x=>x.checked=e.target.checked);
$("#bulkEnable").onclick=()=>bulk("enable");$("#bulkDisable").onclick=()=>bulk("disable");$("#bulkDelete").onclick=()=>bulk("delete");
$("#backupNow").onclick=async()=>{const r=await fetch("/api/backup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"create"})});const j=await r.json();toast(r.ok?"Backup created":(j.error||"Backup failed"));refreshEvents()};
$("#restoreLatest").onclick=async()=>{if(!confirm("Restore the latest backup and restart core services?"))return;const r=await fetch("/api/backup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"restore"})});const j=await r.json();toast(r.ok?"Restore complete":(j.error||"Restore failed"));if(r.ok)setTimeout(()=>location.reload(),2500)};
$("#renewCert").onclick=async()=>{if(!confirm("Force certificate renewal now?"))return;const r=await fetch("/api/certificate/renew",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});const j=await r.json();toast(r.ok?"Certificate renewed":(j.error||"Renewal failed"));refreshSecurity()};
async function refreshExpiry(){
  try{
    const r=await fetch("/api/users",{cache:"no-store"});if(!r.ok)return;const rows=await r.json(), box=document.getElementById("expiryList");if(!box)return;
    const soon=rows.filter(x=>x.days_remaining!==null&&x.days_remaining<=7);
    box.innerHTML=soon.length?soon.map(x=>"<div class='service-card'><span>"+x.username+" • "+x.protocol+"</span><strong class='"+(x.days_remaining<=1?"dangertext":"warn")+"'>"+(x.days_remaining===0?"Expires today":x.days_remaining+" days")+"</strong></div>").join(""):"<div class='muted'>No accounts expire within seven days.</div>";
  }catch(_){}
}
refreshExpiry();setInterval(refreshExpiry,30000);
$("#speedtest").onclick=async()=>{
  const out=$("#speedout");out.style.display="block";out.textContent="Running Ookla Speedtest…";
  const r=await fetch("/api/speedtest"),j=await r.json();out.textContent=j.output||j.error||"No result";
};

function fmtBytes(n){
  n=Math.max(Number(n||0),0);
  const u=["B","KB","MB","GB","TB","PB"]; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return n.toFixed(2)+" "+u[i];
}
async function refreshUsage(){
  try{
    const r=await fetch("/api/usage",{cache:"no-store"}); if(!r.ok)return;
    const j=await r.json();
    const sd=document.getElementById("serverDaily"), sa=document.getElementById("serverAll");
    if(sd)sd.textContent=fmtBytes(j.server.daily_bytes);
    if(sa)sa.textContent=fmtBytes(j.server.all_time_bytes);
    for(const a of j.accounts||[]){
      const all=document.getElementById("alltime-"+a.id), daily=document.getElementById("daily-"+a.id);
      if(a.protocol==="SSH") continue;
      if(all)all.textContent=fmtBytes(a.all_time_bytes);
      if(daily)daily.textContent="Today: "+fmtBytes(a.daily_bytes);
    }
    const stamp=document.getElementById("usageStamp");
    if(stamp)stamp.textContent="Usage updated "+new Date((j.updated_at||Date.now()/1000)*1000).toLocaleTimeString();
  }catch(_){}
}
refreshUsage();
setInterval(refreshUsage,10000);

function fmtRate(n){return fmtBytes(Number(n||0))+"/s"}
async function refreshMetrics(){
  try{
    const r=await fetch("/api/metrics",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const load=(j.cpu_load||[0])[0], mem=j.memory||{}, disk=j.disk||{}, net=j.network||{};
    const cpu=document.getElementById("cpuLoad"), mm=document.getElementById("memUse"), dd=document.getElementById("diskUse");
    if(cpu)cpu.textContent=Number(load||0).toFixed(2);
    if(mm)mm.textContent=fmtBytes(mem.used||0)+" / "+fmtBytes(mem.total||0);
    if(dd)dd.textContent=fmtBytes(disk.used||0)+" / "+fmtBytes(disk.total||0);
    const rx=document.getElementById("rxRate"),tx=document.getElementById("txRate");
    if(rx)rx.textContent=fmtRate(net.rx_bps);
    if(tx)tx.textContent=fmtRate(net.tx_bps);
  }catch(_){}
}
async function refreshSessions(){
  try{
    const r=await fetch("/api/sessions",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const body=document.getElementById("sessionsBody"); if(!body)return;
    const rows=j.sessions||[];
    document.getElementById("sessionCount").textContent=String(rows.length);
    body.innerHTML=rows.length?rows.map(x=>"<tr><td>"+(x.process||"—")+"</td><td>"+(x.user||"—")+"</td><td>"+(x.local||"—")+"</td><td>"+(x.remote||"—")+"</td><td>"+(x.pid||"—")+"</td></tr>").join(""):"<tr><td colspan='5' class='muted'>No established TCP sessions.</td></tr>";
  }catch(_){}
}
async function refreshSecurity(){
  try{
    const [s,c]=await Promise.all([fetch("/api/security",{cache:"no-store"}),fetch("/api/certificate",{cache:"no-store"})]);
    const j=await s.json(), cert=await c.json();
    const fs=document.getElementById("f2bState"), cs=document.getElementById("certState");
    if(fs)fs.textContent=(j.fail2ban||"unknown").toUpperCase()+" • "+(j.banned||0)+" banned";
    if(cs){cs.textContent=cert.ok?(cert.days_remaining+" days remaining"):"Unavailable";cs.className=cert.ok&&cert.days_remaining>14?"metric-good":(cert.days_remaining>=0?"warn":"dangertext")}
    const g=document.getElementById("securityGrid");
    if(g)g.innerHTML=[
      ["Fail2Ban",String(j.fail2ban||"unknown").toUpperCase()],
      ["Banned IPs",String(j.banned||0)],
      ["SSH failures / 24h",String(j.failed_ssh_24h||0)],
      ["Firewall rules",String(j.firewall_rules||0)],
      ["SSH password auth",String((j.ssh_auth||{}).passwordauthentication||"unknown").toUpperCase()],
      ["Certificate",cert.ok?(cert.days_remaining+" days left"):"Unavailable"]
    ].map(x=>"<div class='service-card'><span>"+x[0]+"</span><strong>"+x[1]+"</strong></div>").join("");
  }catch(_){}
}
async function refreshEvents(){
  try{
    const r=await fetch("/api/events",{cache:"no-store"}); if(!r.ok)return; const j=await r.json();
    const e=document.getElementById("events"); if(!e)return;
    e.innerHTML=(j.events||[]).slice(0,30).map(x=>"<div class='event'><strong>"+x.action+(x.username?" • "+x.username:"")+"</strong><small>"+new Date(x.created_at*1000).toLocaleString()+" "+(x.details||"")+"</small></div>").join("")||"<div class='muted'>No activity yet.</div>";
  }catch(_){}
}
function drawUsageChart(data){
  const canvas=document.getElementById("usageChart"); if(!canvas)return;
  const ctx=canvas.getContext("2d"),w=canvas.clientWidth||600,h=120,dpr=window.devicePixelRatio||1;
  canvas.width=w*dpr;canvas.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
  ctx.strokeStyle="rgba(66,245,141,.18)";ctx.lineWidth=1;
  for(let y=20;y<h;y+=25){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  if(!data.length)return;
  const max=Math.max(...data,1), step=w/Math.max(data.length-1,1);
  ctx.strokeStyle="#42f58d";ctx.lineWidth=2;ctx.beginPath();
  data.forEach((v,i)=>{const x=i*step,y=h-10-(v/max)*(h-25);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke();
}
async function refreshChart(){
  try{
    const r=await fetch("/api/usage-history",{cache:"no-store"});if(!r.ok)return;const j=await r.json();drawUsageChart(j.values||[]);
  }catch(_){}
}
refreshMetrics();refreshSessions();refreshSecurity();refreshEvents();refreshChart();
setInterval(refreshMetrics,10000);setInterval(refreshSessions,10000);setInterval(refreshSecurity,30000);setInterval(refreshEvents,15000);setInterval(refreshChart,60000);
document.getElementById("refreshSessions").onclick=refreshSessions;
</script>
</body></html>"""
            page=page.replace('__ROWS__',rows_html)
            page=page.replace('__ACCOUNT_CARDS__',cards_html)
            page=page.replace('__SERVICES__',service_html)
            page=page.replace('__REBOOT__',html.escape(reboot,quote=True))
            page=page.replace('__PANEL_URL__',html.escape(f'http://{public_host()}:{PORT}/',quote=True))
            page=page.replace('__DOMAIN__',html.escape(public_host()))
            page=page.replace('__IP__',html.escape(public_ip()))
            os_name=os.uname().sysname+' '+os.uname().release
            try:
                with open('/etc/os-release') as fh:
                    vals={}
                    for line in fh:
                        if '=' in line:
                            k,v=line.rstrip().split('=',1)
                            vals[k]=v.strip().strip('"')
                os_name=vals.get('PRETTY_NAME',os_name)
            except Exception:
                pass
            page=page.replace('__OS__',html.escape(os_name))
            page=page.replace('__TOTAL__',str(len(rows)))
            page=page.replace('__ACTIVE__',str(active))
            page=page.replace('__SERVER_DAILY__',_human_bytes(server_daily))
            page=page.replace('__SERVER_ALL__',_human_bytes(server_all))
            b=page.encode()

            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path=='/setup':
            try: d=body(self)
            except ValueError as e: return send(self,{'error':str(e)},400)
            except Exception: return send(self,{'error':'invalid JSON'},400)
            username=str(d.get('username','')).strip()
            password=str(d.get('password',''))
            confirm=str(d.get('confirm',''))
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',username): return send(self,{'error':'Username must contain only letters, numbers, dots, underscores or hyphens.'},400)
            if username.lower()=='spiderman': return send(self,{'error':'Choose a different username.'},400)
            if len(password)<8 or len(password)>128 or '\n' in password or '\r' in password or '\x00' in password: return send(self,{'error':'Password must be 8-128 characters and cannot contain newlines.'},400)
            if password!=confirm: return send(self,{'error':'Passwords do not match.'},400)
            try:
                with SETUP_LOCK:
                    if admin_configured(): return send(self,{'error':'Initial setup has already been completed.'},409)
                    _save_admin_credentials(username,password)
                    cookie=_session_cookie(username)
                payload=json.dumps({'ok':True,'message':'Credentials saved. Logging in.'}).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Cache-Control','no-store')
                self.send_header('Set-Cookie',f'{SESSION_COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}')
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
            except Exception as e: return send(self,{'error':str(e)},500)
            return
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
        except ValueError as e: return send(self,{'error':str(e)},400)
        except Exception: return send(self,{'error':'invalid JSON'},400)

        if self.path=='/api/backup':
            action=str(d.get('action','')).lower()
            if action=='create':
                try:
                    p=subprocess.run(['/usr/local/sbin/unified-vps-backup'],capture_output=True,text=True,timeout=120)
                    if p.returncode: return send(self,{'error':(p.stderr or p.stdout).strip() or 'backup failed'},500)
                    log_event('backup_created',os.path.basename(p.stdout.strip()),'')
                    return send(self,{'ok':True,'path':p.stdout.strip()})
                except Exception as e: return send(self,{'error':str(e)},500)
            if action=='restore':
                files=sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)
                if not files: return send(self,{'error':'no backup available'},404)
                p=subprocess.run(['tar','-tzf',files[0]],capture_output=True,text=True,timeout=30)
                if p.returncode: return send(self,{'error':'latest backup is invalid'},500)
                p=subprocess.run(['tar','-xzf',files[0],'-C','/'],capture_output=True,text=True,timeout=120)
                if p.returncode: return send(self,{'error':(p.stderr or 'restore failed').strip()},500)
                log_event('backup_restored',os.path.basename(files[0]),'')
                result=send(self,{'ok':True,'path':files[0],'message':'Restore applied; services will restart shortly.'})
                def restart_restored_services():
                    subprocess.run(['systemctl','daemon-reload'],capture_output=True)
                    subprocess.run(['systemctl','restart','nginx','xray','hysteria-server','haproxy','unified-vps-panel','unified-vps-wstunnel-ssh','unified-vps-ws-payload-ssh'],capture_output=True)
                threading.Timer(2.0,restart_restored_services).start()
                return result
            return send(self,{'error':'unsupported backup action'},400)

        if self.path=='/api/certificate/renew':
            with CERT_LOCK:
                haproxy_was_active=subprocess.run(['systemctl','is-active','--quiet','haproxy'],check=False).returncode==0
                try:
                    acme='/root/.acme.sh/acme.sh'
                    if not os.path.exists(acme): return send(self,{'error':'acme.sh not installed'},500)
                    renew_args=[acme,'--renew','-d',public_host(),'--force']
                    if haproxy_was_active:
                        renew_args += ['--pre-hook','systemctl stop haproxy','--post-hook','systemctl start haproxy']
                    p=subprocess.run(renew_args,capture_output=True,text=True,timeout=180)
                    if p.returncode:
                        return send(self,{'error':(p.stderr or p.stdout).strip() or 'certificate renewal failed'},500)
                    log_event('certificate_renewed',public_host(),'')
                    return send(self,{'ok':True,'output':(p.stdout or '').strip()})
                except Exception as e:
                    return send(self,{'error':str(e)},500)
                finally:
                    if haproxy_was_active:
                        subprocess.run(['systemctl','start','haproxy'],capture_output=True)

        if self.path=='/api/users':
            try: return send(self,create_user(d))
            except Exception as e: return send(self,{'error':str(e)},500)
        if self.path=='/api/users/bulk':
            ids=[int(x) for x in d.get('ids',[]) if str(x).isdigit()]
            action=str(d.get('action','')).lower()
            if not ids or action not in ('enable','disable','delete','renew'):
                return send(self,{'error':'invalid bulk request'},400)
            if action=='renew':
                try: renew_days=int(d.get('days',0) or 0)
                except (TypeError,ValueError): return send(self,{'error':'renewal days required'},400)
                if renew_days<=0 or renew_days>36500: return send(self,{'error':'renewal days must be between 1 and 36500'},400)
            results=[]
            for uid in ids:
                try:
                    c=conn(); row=c.execute('select * from users where id=?',(uid,)).fetchone(); c.close()
                    if not row: results.append({'id':uid,'ok':False,'error':'not found'}); continue
                    if action=='delete':
                        if row['protocol']=='SSH': del_ssh(row['username'])
                        elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
                        else: del_xray(row['protocol'],row['username'])
                        c=conn(); c.execute('delete from users where id=?',(uid,)); c.commit(); c.close()
                    elif action in ('enable','disable'):
                        enable=action=='enable'
                        if enable:
                            err=account_enable_error(row)
                            if err: raise ValueError(err)
                        if row['protocol'] in XRAY_TAGS:
                            if enable: ensure_xray_client(row['protocol'],row['username'],row['secret'])
                            else: del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='Hysteria' and not enable:
                            kick_hysteria(row['username'])
                        elif row['protocol']=='SSH': set_ssh_enabled(row['username'],enable,row['expiry'])
                        c=conn(); c.execute('update users set enabled=? where id=?',(1 if enable else 0,uid)); c.commit(); c.close()
                    else:
                        days=int(d.get('days',0));
                        if days <= 0: raise ValueError('renewal days must be greater than 0')
                        exp=int(time.time())+days*86400
                        if row['protocol'] in XRAY_TAGS:
                            ensure_xray_client(row['protocol'],row['username'],row['secret'])
                        elif row['protocol']=='SSH':
                            set_ssh_enabled(row['username'],True,exp)
                        baseline=int(row['raw_bytes'] or 0)
                        if row['protocol']=='Hysteria':
                            hstats=_hysteria_usage()
                            if isinstance(hstats,dict): baseline=int(hstats.get(row['username'],baseline))
                        elif row['protocol'] in XRAY_TAGS:
                            baseline=0
                        c=conn(); c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',(exp,baseline,time.strftime('%Y-%m-%d'),uid)); c.commit(); c.close()
                    log_event('bulk_'+action,row['protocol'],row['username'])
                    results.append({'id':uid,'ok':True})
                except Exception as e:
                    results.append({'id':uid,'ok':False,'error':str(e)})
            return send(self,{'ok':all(x['ok'] for x in results),'results':results})

        if self.path=='/api/users/action':
            c=conn(); row=c.execute('select * from users where id=?',(int(d.get('id',0)),)).fetchone()
            if not row: c.close(); return send(self,{'error':'not found'},404)
            action=str(d.get('action','')).lower()
            try:
                if action=='renew':
                    days=int(d.get('days',0) or 0)
                    if days <= 0: raise ValueError('renewal days must be greater than 0')
                    if days > 36500: raise ValueError('renewal days exceeds maximum supported duration')
                    exp=int(time.time())+days*86400
                    baseline=int(row['raw_bytes'] or 0)
                    if row['protocol']=='Hysteria':
                        hstats=_hysteria_usage()
                        if isinstance(hstats,dict): baseline=int(hstats.get(row['username'],baseline))
                    elif row['protocol'] in XRAY_TAGS:
                        baseline=0
                    c.execute('update users set expiry=?,enabled=1,used_bytes=0,raw_bytes=?,daily_used_bytes=0,usage_day=? where id=?',(exp,baseline,time.strftime('%Y-%m-%d'),row['id']))
                    if row['protocol'] in XRAY_TAGS:
                        ensure_xray_client(row['protocol'],row['username'],row['secret'])
                    elif row['protocol']=='SSH':
                        set_ssh_enabled(row['username'],True,exp)
                    c.commit()
                    log_event('account_renewed',f'{days} days',row['username'])
                    return send(self,{'ok':True,'action':'renew','id':row['id']})
                if action in ('enable','disable'):
                    enable=action=='enable'
                    if enable:
                        err=account_enable_error(row)
                        if err: raise ValueError(err)
                    if enable:
                        if row['protocol'] in XRAY_TAGS:
                            with XRAY_LOCK:
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
                            set_ssh_enabled(row['username'],True,row['expiry'])
                    else:
                        if row['protocol'] in XRAY_TAGS:
                            del_xray(row['protocol'],row['username'])
                        elif row['protocol']=='Hysteria':
                            kick_hysteria(row['username'])
                        elif row['protocol']=='SSH':
                            set_ssh_enabled(row['username'],False)
                    c.execute('update users set enabled=? where id=?',(1 if enable else 0,row['id']))
                    c.commit()
                    log_event('account_'+action,row['protocol'],row['username'])
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
                elif row['protocol']=='Hysteria': kick_hysteria(row['username'])
                else: del_xray(row['protocol'],row['username'])
                c.execute('delete from users where id=?',(row['id'],)); c.commit()
                log_event('account_deleted',row['protocol'],row['username'])
                return send(self,{'ok':True})
            except Exception as e: c.rollback(); return send(self,{'error':str(e)},500)
            finally: c.close()
        return send(self,{'error':'not found'},404)

if __name__=='__main__':
    conn().close()
    threading.Thread(target=sync_usage,daemon=True).start()
    ThreadingHTTPServer((os.environ.get('PANEL_BIND','0.0.0.0'),PORT),H).serve_forever()
