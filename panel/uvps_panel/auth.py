import base64
import hashlib
import hmac
import json
import os
import re
from .config import ADMIN_FILE,BASE,LOGIN_FAILURES,LOGIN_LOCK,LOGIN_MAX_FAILURES,LOGIN_WINDOW,PANEL_ENV,SESSION_COOKIE,SESSION_TTL

ADMIN=os.environ.get('ADMIN_USER','').strip()
PASSWORD=os.environ.get('ADMIN_PASSWORD','')

def _load_admin_credentials():
    global ADMIN,PASSWORD
    try:
        st=os.stat(ADMIN_FILE)
        if st.st_uid != 0:
            return
        os.chmod(ADMIN_FILE,0o600)
        with open(ADMIN_FILE,encoding='utf-8') as f:
            data=json.load(f)
        user=str(data.get('username','')).strip()
        password=str(data.get('password',''))
        if hashlib.sha256(f'{user}:{password}'.encode()).hexdigest() == '89b4cdab4d0d839fcf432ca76640ffe90da27a63b6f0ad7bbf1d644f5ccd91a9':
            try: os.unlink(ADMIN_FILE)
            except OSError: pass
            ADMIN=''
            PASSWORD=''
            return
        valid_user=bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{2,31}',user))
        valid_password=8 <= len(password) <= 128 and '\n' not in password and '\r' not in password
        if valid_user and valid_password:
            ADMIN=user
            PASSWORD=password
            return
        try: os.unlink(ADMIN_FILE)
        except OSError: pass
    except Exception:
        pass

_load_admin_credentials()
if hashlib.sha256(f'{ADMIN}:{PASSWORD}'.encode()).hexdigest() == '89b4cdab4d0d839fcf432ca76640ffe90da27a63b6f0ad7bbf1d644f5ccd91a9':
    ADMIN=''
    PASSWORD=''
    try:
        with open(PANEL_ENV,encoding='utf-8') as f: lines=f.read().splitlines()
        lines=[line for line in lines if not line.startswith('ADMIN_USER=') and not line.startswith('ADMIN_PASSWORD=')]
        lines += ['ADMIN_USER=','ADMIN_PASSWORD=']
        tmp_env=PANEL_ENV+'.tmp'
        with open(tmp_env,'w',encoding='utf-8') as f: f.write('\n'.join(lines)+'\n')
        os.chmod(tmp_env,0o600)
        os.replace(tmp_env,PANEL_ENV)
    except OSError:
        pass

def admin_configured():
    return bool(ADMIN and PASSWORD)

def _session_cookie(username):
    issued=str(int(time.time()))
    payload=f'{username}|{issued}'
    sig=hmac.new(f'{ADMIN}\\0{PASSWORD}'.encode(),payload.encode(),hashlib.sha256).hexdigest()
    return f'{payload}|{sig}'

def _session_valid(cookie):
    if not admin_configured() or not cookie: return False
    try:
        username,issued,sig=cookie.split('|',2)
        issued=int(issued)
        if username!=ADMIN or issued<0 or time.time()-issued>SESSION_TTL: return False
        expected=hmac.new(f'{ADMIN}\\0{PASSWORD}'.encode(),f'{username}|{issued}'.encode(),hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig,expected)
    except Exception:
        return False

def auth(h,basic_allowed=False):
    if not admin_configured(): return False
    if basic_allowed:
        v=h.get('Authorization','')
        if v.startswith('Basic '):
            try:
                u,p=base64.b64decode(v[6:]).decode().split(':',1)
                if hmac.compare_digest(u,ADMIN) and hmac.compare_digest(p,PASSWORD): return True
            except Exception: pass
    for item in h.get('Cookie','').split(';'):
        item=item.strip()
        if item.startswith(SESSION_COOKIE+'=') and _session_valid(item.split('=',1)[1]): return True
    return False

def _save_admin_credentials(username,password):
    global ADMIN,PASSWORD
    os.makedirs(BASE,exist_ok=True)
    data={'username':str(username),'password':str(password)}
    tmp=ADMIN_FILE+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False); f.write('\n')
    os.chmod(tmp,0o600)
    os.replace(tmp,ADMIN_FILE)
    # Keep legacy EnvironmentFile credentials blank so the secret is not
    # copied into a shell-readable environment configuration.
    try:
        with open(PANEL_ENV,encoding='utf-8') as f: lines=f.read().splitlines()
        lines=[line for line in lines if not line.startswith('ADMIN_USER=') and not line.startswith('ADMIN_PASSWORD=')]
        lines += ['ADMIN_USER=','ADMIN_PASSWORD=']
        tmp_env=PANEL_ENV+'.tmp'
        with open(tmp_env,'w',encoding='utf-8') as f: f.write('\n'.join(lines)+'\n')
        os.chmod(tmp_env,0o600); os.replace(tmp_env,PANEL_ENV)
    except OSError:
        pass
    ADMIN=str(username); PASSWORD=str(password)

_load_admin_credentials()
if hashlib.sha256(f'{ADMIN}:{PASSWORD}'.encode()).hexdigest() == '89b4cdab4d0d839fcf432ca76640ffe90da27a63b6f0ad7bbf1d644f5ccd91a9':
    ADMIN=''
    PASSWORD=''
    try:
        with open(PANEL_ENV,encoding='utf-8') as f: lines=f.read().splitlines()
        lines=[line for line in lines if not line.startswith('ADMIN_USER=') and not line.startswith('ADMIN_PASSWORD=')]
        lines += ['ADMIN_USER=','ADMIN_PASSWORD=']
        tmp_env=PANEL_ENV+'.tmp'
        with open(tmp_env,'w',encoding='utf-8') as f: f.write('\\n'.join(lines)+'\\n')
        os.chmod(tmp_env,0o600)
        os.replace(tmp_env,PANEL_ENV)
    except OSError:
        pass
