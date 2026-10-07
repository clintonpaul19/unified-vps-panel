import html
import os
import secrets
import time
from .config import PANEL_BUILD,PORT,SSH_PORTS,XRAY_TAGS
from .accounts import record
from .db import conn
from .http_utils import send_html
from .system import public_host,public_ip,_human_bytes,service_states

def setup_page(r):
    token=secrets.token_urlsafe(32)
    page='''<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unified VPS Setup</title>
<style>body{font:15px system-ui;background:#06110b;color:#ecfff2;display:grid;place-items:center;min-height:100vh;margin:0}.card{width:min(420px,90%);padding:28px;border:1px solid #173524;border-radius:16px;background:#0b1811}.card h2{margin-top:0}input,button{width:100%;box-sizing:border-box;padding:12px;margin:7px 0;border-radius:9px;border:1px solid #173524;background:#06100a;color:#ecfff2}button{background:#42f58d;color:#03200f;font-weight:800;cursor:pointer}.msg{color:#ff6b78;min-height:20px}</style>
<div class="card"><h2>Unified VPS</h2><p>Create the administrator credentials for this VPS.</p><form id="setupForm" method="post" action="/setup"><input type="hidden" name="setup_token" value="__SETUP_TOKEN__"><input name="username" placeholder="Enter username" maxlength="32" autocomplete="username" required><input name="password" type="password" placeholder="Enter password" minlength="8" maxlength="128" autocomplete="new-password" required><input name="confirm" type="password" placeholder="Reenter password" minlength="8" maxlength="128" autocomplete="new-password" required><button type="submit">Save and login</button><div class="msg" id="setupMsg"></div></form></div><script>const form=document.getElementById('setupForm'),msg=document.getElementById('setupMsg');form.addEventListener('submit',async e=>{e.preventDefault();msg.textContent='';const d=Object.fromEntries(new FormData(form));if(d.password!==d.confirm){msg.textContent='Passwords do not match.';return}try{const r=await fetch('/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d),cache:'no-store'});const text=await r.text();let j={};try{j=JSON.parse(text)}catch(_){j={error:text||'Server returned an invalid response.'}}if(!r.ok){msg.textContent=j.error||'Setup failed.';return}window.location.replace('/');}catch(_){msg.textContent='Unable to reach the panel. Try again.'}});</script></div>'''.replace('__SETUP_TOKEN__',token)
    return send_html(r,page,headers={'Set-Cookie':f'uvps_setup_nonce={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=600','Pragma':'no-cache'})

def login_page(r):
    token=secrets.token_urlsafe(32)
    page='''<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unified VPS Login</title>
<style>body{font:15px system-ui;background:#06110b;color:#ecfff2;display:grid;place-items:center;min-height:100vh;margin:0}.card{width:min(420px,90%);padding:28px;border:1px solid #173524;border-radius:16px;background:#0b1811}.card h2{margin-top:0}input,button{width:100%;box-sizing:border-box;padding:12px;margin:7px 0;border-radius:9px;border:1px solid #173524;background:#06100a;color:#ecfff2}button{background:#42f58d;color:#03200f;font-weight:800;cursor:pointer}.msg{color:#ff6b78;min-height:20px}</style>
<div class="card"><h2>Unified VPS</h2><form id="loginForm"><input type="hidden" name="login_token" value="__LOGIN_TOKEN__"><input name="username" placeholder="Username" autocomplete="username" required><input name="password" type="password" placeholder="Password" autocomplete="current-password" required><button type="submit">Login</button><div class="msg" id="loginMsg"></div></form></div><script>const form=document.getElementById('loginForm'),msg=document.getElementById('loginMsg');form.addEventListener('submit',async e=>{e.preventDefault();msg.textContent='';try{const d=Object.fromEntries(new FormData(form)),r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d),cache:'no-store'}),text=await r.text();let j={};try{j=JSON.parse(text)}catch(_){j={error:text||'Server returned an invalid response.'}}if(!r.ok){msg.textContent=j.error||'Login failed.';return}window.location.replace('/');}catch(_){msg.textContent='Unable to reach the panel. Try again.'}});</script></div>'''.replace('__LOGIN_TOKEN__',token)
    return send_html(r,page,headers={'Set-Cookie':f'uvps_login_nonce={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=600','Pragma':'no-cache'})

def dashboard_page():
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
    svc=service_states(('ssh','nginx','haproxy','xray','hysteria-server','unified-vps-panel'))
    services={
        'SSH':svc.get('ssh','unknown'),
        'NGINX':svc.get('nginx','unknown'),
        'HAProxy':svc.get('haproxy','unknown'),
        'Xray':svc.get('xray','unknown'),
        'Hysteria 2':svc.get('hysteria-server','unknown'),
        'Panel':svc.get('unified-vps-panel','unknown')
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
                uris.append(f'<div class="copyline"><code>Credential hidden</code><button class="copy-btn" data-copy-id="{xid}" data-copy-key="{port}" type="button">Copy {port}</button></div>')
            connection='<div class="uri-stack">'+''.join(uris)+'</div>'
        elif protocol=='SSH':
            parts=[]
            for label,key in (('WS 80','WebSocket'),('WS 8080','WebSocket8080'),('WS 8880','WebSocket8880'),('WSS 443','WebSocketTLS'),('WSS 8443','WebSocketTLS8443')):
                uri=html.escape(x['uris'].get(key,''),quote=True)
                parts.append(f'<div class="copyline"><code>{uri}</code><button class="copy-btn" data-copy="{uri}" type="button">Copy</button></div>')
            connection=f'<div class="sshmeta"><span>Host: {html.escape(x["host"],quote=True)}</span><span>Path: {html.escape(x["uris"].get("Path","/ssh"),quote=True)}</span></div><div class="uri-stack">{"".join(parts)}</div>'
        else:
            connection=f'<div class="copyline"><code>Credential hidden</code><button class="copy-btn" data-copy-id="{xid}" data-copy-key="53" type="button">Copy URI</button></div>'
        expiry_class='warn' if x['expiry'] and x['expiry']<=time.time()+7*86400 else ''
        expiry_notice='<span class="muted warn">Expires soon</span>' if expiry_class else ''
        rows_html.append(
            f'<tr data-row data-id="{xid}" data-user="{username}" data-protocol="{html.escape(protocol.lower())}">'
            f'<td><input class="rowcheck" type="checkbox" value="{xid}"></td><td><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{username}</strong><span class="muted">{html.escape(protocol)}</span></div></div></td>'
            f'<td>{state_badge("active" if enabled else "disabled")}</td>'
            f'<td><span class="pill">{html.escape(str(x["port"]))}</span></td>'
            f'<td><button class="secret-btn" data-user-id="{xid}" type="button">Reveal</button></td>
            f'<td><span id="alltime-{xid}">{usage_text}</span><span class="muted"> / {quota}</span><span id="daily-{xid}" class="muted">{daily_text}</span></td>'
            f'<td><span class="muted {expiry_class}">{html.escape(expiry)}</span>{expiry_notice}</td>'
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
        card_expiry_class='warn' if expiry_warn else ''
        card_action='disable' if enabled else 'enable'
        card_action_label='Disable' if enabled else 'Enable'
        cards_html.append(
            f'<article class="account-card" data-card-user="{html.escape(x["username"],quote=True)}" data-card-protocol="{html.escape(protocol.lower())}">'
            f'<div class="cardtop"><div class="usercell"><div class="avatar">{html.escape(x["username"][0].upper())}</div><div><strong>{html.escape(x["username"])}</strong><span class="muted">{html.escape(protocol)}</span></div></div>{state_badge("active" if enabled else "disabled")}</div>'
            f'<div class="cardstats"><div><span>Today</span><strong>{today}</strong></div><div><span>All time</span><strong>{usage}</strong></div><div><span>Expiry</span><strong class="{card_expiry_class}">{html.escape(expiry)}</strong></div></div>'
            f'<div class="cardactions"><button class="ghost" data-action="{card_action}" data-id="{xid}" type="button">{card_action_label}</button><button class="danger" data-delete="{xid}" type="button">Delete</button></div>'
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
.overlay{position:fixed;inset:0;background:rgba(1,7,4,.72);backdrop-filter:blur(10px);display:none;align-items:center;justify-content:center;padding:20px;z-index:30}.overlay.open{display:flex}.modal{width:min(560px,100%);background:#09170f;border:1px solid var(--line);border-radius:18px;box-shadow:0 30px 90px rgba(0,0,0,.5);padding:20px}.modalhead{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px}.modalhead h3{margin:0}.modalhead p{margin:4px 0;color:var(--muted);font-size:12px}.close{border:1px solid var(--line);background:#07110b;color:#b4c9bc;border-radius:8px;padding:6px 9px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{display:grid;gap:6px}.field[hidden]{display:none!important}.field.full{grid-column:1/-1}.field label{font-size:11px;color:var(--muted)}.field input,.field select{padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#06100a;color:var(--text);outline:none}.modalfoot{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}.secondary{border:1px solid var(--line);background:#08140c;color:#b9d0c2;border-radius:10px;padding:10px 13px}
.toast{position:fixed;right:20px;bottom:20px;z-index:50;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:#0c1d13;color:var(--text);box-shadow:var(--shadow);display:none}.toast.show{display:block}.account-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:14px}.account-card{border:1px solid var(--line);border-radius:14px;padding:14px;background:linear-gradient(180deg,rgba(15,36,24,.78),rgba(7,18,12,.78))}.cardtop{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.cardstats{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin:13px 0}.cardstats div{padding:8px;border-radius:9px;background:rgba(255,255,255,.025);border:1px solid var(--line)}.cardstats span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase}.cardstats strong{display:block;margin-top:3px;font-size:11px}.cardactions{display:flex;gap:7px}.account-card .danger{margin-left:auto}.eventlist{display:grid;gap:7px;max-height:260px;overflow:auto}.event{padding:9px 10px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.02)}.event strong{font-size:11px}.event small{display:block;color:var(--muted);margin-top:2px}.warn{color:#ffd166!important}.dangertext{color:var(--danger)!important}.metric-good{color:var(--accent)!important}
@media(max-width:1050px){.app{grid-template-columns:1fr}.sidebar{display:none}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}.account-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar{padding:0 16px}.content{padding:18px}}
@media(max-width:620px){.stats{grid-template-columns:1fr}.account-cards{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero h3{font-size:23px}.formgrid{grid-template-columns:1fr}.field.full{grid-column:auto}.top-actions .badge{display:none}.accounts .panelhead{display:block}.accounts .panelhead>div:first-child{margin-bottom:12px}.accounts .toolbar{display:grid;grid-template-columns:1fr 1fr;gap:8px}.accounts .toolbar .search{min-width:0;grid-column:1/-1}.accounts .toolbar .select{min-width:0}.accounts .toolbar button{min-width:0}.services{grid-template-columns:1fr}.modal{padding:17px}.modalfoot{flex-wrap:wrap}.modalfoot>*{flex:1}.copyline{max-width:100%}}
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
  <header class="topbar"><div><h2>Command Center</h2><p>__DOMAIN__</p><p class="muted">Build __BUILD__</p></div><div class="top-actions"><span class="badge">IPv4 __IP__</span><span class="badge">__OS__</span></div></header>
  <section class="content" id="dashboard">
<div class="hero"><div><h3>Server overview</h3><p>Live account inventory, services and transport endpoints.</p><span id="usageStamp" class="muted" style="margin-top:6px">Usage updating…</span></div><button class="primary" id="openCreate" type="button" onclick="document.getElementById('modal').classList.add('open')">+ Create account</button></div>
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
<div class="modalhead"><div><h3>Create account</h3><p>Provision a new Unified VPS identity.</p></div><button class="close" id="closeCreate" type="button" onclick="document.getElementById('modal').classList.remove('open')">Close</button></div>
<form id="createForm">
  <div class="formgrid">
<div class="field"><label>Username</label><input name="username" required maxlength="32"></div>
<div class="field"><label>Protocol</label><select name="protocol" id="protocol"><option>SSH</option><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Hysteria</option></select></div>
<div class="field full" id="sshSecretField" hidden><label id="sshSecretLabel">SSH password</label><input name="secret" id="sshSecret" type="password" autocomplete="new-password"></div>
<div class="field"><label>Duration (days)</label><input name="days" type="number" min="0" value="0"></div>
<div class="field"><label>Quota (GB)</label><input name="quota_gb" id="quota" type="number" min="0" step="0.1" value="0"></div>
  </div>
  <div class="modalfoot"><button class="secondary" id="cancelCreate" type="button" onclick="document.getElementById('modal').classList.remove('open')">Cancel</button><button class="primary" type="submit">Create account</button></div>
</form>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const $=s=>document.querySelector(s);
window.addEventListener("error",e=>{const el=document.getElementById("events");if(el&&e.message)el.innerHTML="<div class='muted'>Panel script error: "+String(e.message).replace(/[&<>"]/g,"")+"</div>"});
window.addEventListener("unhandledrejection",e=>{const el=document.getElementById("events");if(el)el.innerHTML="<div class='muted'>Panel request error: "+String(e.reason||"unknown").replace(/[&<>"]/g,"")+"</div>"});
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
async function fetchCredential(id){
  const r=await fetch("/api/users/secret?id="+encodeURIComponent(id),{credentials:"same-origin"});
  const j=await r.json();
  if(!r.ok) throw new Error(j.error||"Credential request failed");
  return j;
}
document.addEventListener("click",async e=>{
  const copy=e.target.closest("[data-copy-id]"); if(copy){
    try{
      const j=await fetchCredential(copy.dataset.copyId);
      const value=j.uris?.[copy.dataset.copyKey] || "";
      if(!value) throw new Error("URI unavailable");
      await copyText(value,copy);
    }catch(err){toast(err.message||"Copy failed")}
    return
  }
  const reveal=e.target.closest(".secret-btn"); if(reveal){
    if(reveal.dataset.revealed==="1"){reveal.textContent="Reveal";reveal.dataset.revealed="0";return}
    try{
      const j=await fetchCredential(reveal.dataset.userId);
      reveal.textContent=j.secret||"Unavailable";
      reveal.dataset.revealed="1";
    }catch(err){toast(err.message||"Reveal failed")}
    return
  }
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
const protocol=$("#protocol"), sshField=$("#sshSecretField"), sshSecret=$("#sshSecret"), sshSecretLabel=$("#sshSecretLabel"), quota=$("#quota");
function updateFields(){const ssh=protocol.value==="SSH";sshField.hidden=!ssh;sshField.style.display=ssh?"":"none";sshField.setAttribute("aria-hidden",ssh?"false":"true");sshSecret.required=ssh;sshSecret.disabled=!ssh;if(sshSecretLabel)sshSecretLabel.textContent="SSH password";quota.disabled=ssh;if(ssh)quota.value="0";if(!ssh)sshSecret.value=""}
protocol.onchange=updateFields;updateFields();
$("#createForm").onsubmit=async e=>{
  e.preventDefault();
  const submit=e.target.querySelector("button[type=submit]"); if(submit)submit.disabled=true;
  try{
const f=new FormData(e.target), payload=Object.fromEntries(f.entries());
payload.days=Number(payload.days||0);payload.quota_gb=Number(payload.quota_gb||0);if(payload.protocol!=="SSH")delete payload.secret;
const r=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload),cache:"no-store"});
const text=await r.text(); let j={}; try{j=JSON.parse(text)}catch(_){j={error:text||("HTTP "+r.status)}}
if(!r.ok){toast(j.error||"Account creation failed");return}
location.reload();
  }catch(err){toast("Account creation failed: "+(err.message||"network error"))}
  finally{if(submit)submit.disabled=false}
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
function renderExpiry(rows){
  const box=document.getElementById("expiryList");if(!box)return;
  const soon=(rows||[]).filter(x=>x.days_remaining!==null&&x.days_remaining<=7);
  const esc=v=>String(v??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
  box.innerHTML=soon.length?soon.map(x=>"<div class='service-card'><span>"+esc(x.username)+" • "+esc(x.protocol)+"</span><strong class='"+(x.days_remaining<=1?"dangertext":"warn")+"'>"+(x.days_remaining===0?"Expires today":esc(x.days_remaining)+" days")+"</strong></div>").join(""):"<div class='muted'>No accounts expire within seven days.</div>";
}
$("#speedtest").onclick=async()=>{
  const out=$("#speedout");out.style.display="block";out.textContent="Running Ookla Speedtest…";
  try{
const r=await fetch("/api/speedtest"),j=await r.json();
out.textContent=j.output||j.error||"No result";
  }catch(e){out.textContent="Speedtest unavailable.";toast("Speedtest request failed");}
};

function fmtBytes(n){
  n=Math.max(Number(n||0),0);
  const u=["B","KB","MB","GB","TB","PB"]; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return n.toFixed(2)+" "+u[i];
}
async function refreshUsage(){
  try{
const r=await fetch("/api/usage",{cache:"no-store"}); if(!r.ok)throw new Error("HTTP "+r.status);
const j=await r.json(),accounts=j.accounts||[];
const sd=document.getElementById("serverDaily"), sa=document.getElementById("serverAll");
if(sd)sd.textContent=fmtBytes(j.server.daily_bytes);
if(sa)sa.textContent=fmtBytes(j.server.all_time_bytes);
for(const a of accounts){
  const all=document.getElementById("alltime-"+a.id), daily=document.getElementById("daily-"+a.id);
  if(a.protocol==="SSH") continue;
  if(all)all.textContent=fmtBytes(a.all_time_bytes);
  if(daily)daily.textContent="Today: "+fmtBytes(a.daily_bytes);
}
renderExpiry(accounts);
const stamp=document.getElementById("usageStamp");
if(stamp)stamp.textContent="Usage updated "+new Date((j.updated_at||Date.now()/1000)*1000).toLocaleTimeString();
  }catch(e){
const sd=document.getElementById("serverDaily"),sa=document.getElementById("serverAll"),st=document.getElementById("usageStamp");
if(sd)sd.textContent="Unavailable"; if(sa)sa.textContent="Unavailable"; if(st)st.textContent="Usage unavailable";
  }
}

function fmtRate(n){return fmtBytes(Number(n||0))+"/s"}
async function refreshMetrics(){
  try{
const r=await fetch("/api/metrics",{cache:"no-store"}); if(!r.ok)throw new Error("HTTP "+r.status); const j=await r.json();
const load=(j.cpu_load||[0])[0], mem=j.memory||{}, disk=j.disk||{}, net=j.network||{};
const cpu=document.getElementById("cpuLoad"), mm=document.getElementById("memUse"), dd=document.getElementById("diskUse");
if(cpu)cpu.textContent=Number(load||0).toFixed(2);
if(mm)mm.textContent=fmtBytes(mem.used||0)+" / "+fmtBytes(mem.total||0);
if(dd)dd.textContent=fmtBytes(disk.used||0)+" / "+fmtBytes(disk.total||0);
const rx=document.getElementById("rxRate"),tx=document.getElementById("txRate");
if(rx)rx.textContent=fmtRate(net.rx_bps);
if(tx)tx.textContent=fmtRate(net.tx_bps);
  }catch(e){
const ids=["cpuLoad","memUse","diskUse","rxRate","txRate"]; ids.forEach(id=>{const el=document.getElementById(id);if(el)el.textContent="Unavailable"});
  }
}
async function refreshSessions(){
  try{
const r=await fetch("/api/sessions",{cache:"no-store"}); if(!r.ok)throw new Error("HTTP "+r.status); const j=await r.json();
const body=document.getElementById("sessionsBody"); if(!body)return;
const rows=j.sessions||[];
document.getElementById("sessionCount").textContent=String(rows.length);
const esc=v=>String(v??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
body.innerHTML=rows.length?rows.map(x=>"<tr><td>"+esc(x.process||"—")+"</td><td>"+esc(x.user||"—")+"</td><td>"+esc(x.local||"—")+"</td><td>"+esc(x.remote||"—")+"</td><td>"+esc(x.pid||"—")+"</td></tr>").join(""):"<tr><td colspan='5' class='muted'>No established TCP sessions.</td></tr>";
  }catch(e){
const body=document.getElementById("sessionsBody"); if(body)body.innerHTML="<tr><td colspan='5' class='muted'>Unable to load active connections.</td></tr>";
  }
}
async function refreshSecurity(){
  try{
const r=await fetch("/api/security",{cache:"no-store"});
if(!r.ok)throw new Error("security API unavailable");
const j=await r.json(), cert=j.certificate||{ok:false,error:"Certificate unavailable"};
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
  }catch(e){
const fs=document.getElementById("f2bState"),cs=document.getElementById("certState"); if(fs)fs.textContent="Unavailable"; if(cs)cs.textContent="Unavailable";
const g=document.getElementById("securityGrid"); if(g)g.innerHTML="<div class='service-card'><span>Security telemetry</span><strong>Unavailable</strong></div>";
  }
}
async function refreshEvents(){
  try{
const r=await fetch("/api/events",{cache:"no-store"}); if(!r.ok)throw new Error("HTTP "+r.status); const j=await r.json();
const e=document.getElementById("events"); if(!e)return;
const esc=v=>String(v??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
e.innerHTML=(j.events||[]).slice(0,30).map(x=>"<div class='event'><strong>"+esc(x.action)+(x.username?" • "+esc(x.username):"")+"</strong><small>"+new Date(x.created_at*1000).toLocaleString()+" "+esc(x.details||"")+"</small></div>").join("")||"<div class='muted'>No activity yet.</div>";
  }catch(e){
const el=document.getElementById("events"); if(el)el.innerHTML="<div class='muted'>Unable to load activity events.</div>";
  }
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
const r=await fetch("/api/usage-history",{cache:"no-store"});if(!r.ok)throw new Error("HTTP "+r.status);const j=await r.json();drawUsageChart(j.values||[]);
  }catch(e){
const canvas=document.getElementById("usageChart"); if(canvas){const ctx=canvas.getContext("2d");ctx.clearRect(0,0,canvas.width,canvas.height);ctx.font="13px system-ui";ctx.fillText("Usage history unavailable",12,40);}
  }
}
const pollers=[];
function startPoll(fn,interval){
  let running=false,timer=0;
  const run=async()=>{
if(document.hidden){timer=window.setTimeout(run,interval);return}
if(running)return;
running=true;
try{await fn()}finally{running=false;timer=window.setTimeout(run,interval)}
  };
  const wake=()=>{if(!document.hidden){window.clearTimeout(timer);run()}};
  pollers.push(wake);run();
}
startPoll(refreshUsage,10000);
startPoll(refreshMetrics,10000);
startPoll(refreshSessions,15000);
startPoll(refreshSecurity,30000);
startPoll(refreshEvents,30000);
startPoll(refreshChart,60000);
document.addEventListener("visibilitychange",()=>{if(!document.hidden)pollers.forEach(wake=>wake())});
document.getElementById("refreshSessions").onclick=refreshSessions;
</script>
</body></html>"""
    page=page.replace('__ROWS__',rows_html)
    page=page.replace('__ACCOUNT_CARDS__',cards_html)
    page=page.replace('__SERVICES__',service_html)
    page=page.replace('__REBOOT__',html.escape(reboot,quote=True))
    page=page.replace('__PANEL_URL__',html.escape(f'http://{public_host()}:{PORT}/',quote=True))
    page=page.replace('__DOMAIN__',html.escape(public_host()))
    page=page.replace('__BUILD__',PANEL_BUILD)
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
    return page
