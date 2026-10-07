import json
import os
import subprocess
from .config import CFG,XRAY_LOCK,XRAY_TAGS

def load_xray():
    with open(CFG) as f: return json.load(f)

def save_xray(d):
    with XRAY_LOCK:
        tmp=CFG+'.tmp.json'; rollback=CFG+'.rollback.tmp'
        try:
            with open(CFG,'rb') as f: previous=f.read()
        except OSError: previous=None
        try:
            st=os.stat(CFG); owner=(st.st_uid,st.st_gid)
        except OSError:
            owner=None
        with open(tmp,'w') as f: json.dump(d,f,indent=2)
        os.chmod(tmp,0o640)
        if owner:
            try: os.chown(tmp,owner[0],owner[1])
            except PermissionError: pass
        test=subprocess.run(['xray','-test','-config',tmp],capture_output=True,text=True)
        if test.returncode:
            try: os.unlink(tmp)
            except OSError: pass
            raise RuntimeError('Xray configuration test failed: '+(test.stderr or test.stdout).strip())
        os.replace(tmp,CFG)
        rr=subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
        active=subprocess.run(['systemctl','is-active','--quiet','xray'],check=False).returncode==0
        if rr.returncode or not active:
            if previous is not None:
                try:
                    with open(rollback,'wb') as f: f.write(previous)
                    if owner:
                        try: os.chown(rollback,owner[0],owner[1])
                        except PermissionError: pass
                    os.chmod(rollback,0o640)
                    os.replace(rollback,CFG)
                    subprocess.run(['systemctl','restart','xray'],capture_output=True,text=True)
                except Exception: pass
            err=(rr.stderr or rr.stdout).strip() or 'Xray service did not become active'
            raise RuntimeError('Xray restart failed: '+err)
        try: os.unlink(rollback)
        except OSError: pass

def ensure_xray_client(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            client=next((x for x in clients if x.get('email')==u),None)
            key='id' if protocol in ('VMess','VLESS') else 'password'
            if client is None:
                client={'email':u,'level':0,key:secret}; clients.append(client); changed=True
            elif client.get(key)!=secret:
                client[key]=secret; changed=True
        if changed: save_xray(d)

def add_xray(protocol,u,secret):
    with XRAY_LOCK:
        d=load_xray(); changed=False
        key='id' if protocol in ('VMess','VLESS') else 'password'
        for tag in XRAY_TAGS[protocol]:
            ib=next((i for i in d.get('inbounds',[]) if i.get('tag')==tag),None)
            if ib is None: raise RuntimeError(f'{protocol} inbound missing: {tag}')
            clients=ib.setdefault('settings',{}).setdefault('clients',[])
            client=next((x for x in clients if x.get('email')==u),None)
            if client is None:
                clients.append({'email':u,'level':0,key:secret})
                changed=True
            elif client.get(key)!=secret:
                client[key]=secret
                changed=True
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
