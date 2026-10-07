import os
import pwd
import re
import subprocess
import time
from .cache import cached_value
from .config import DOMAIN

def public_host():
    return DOMAIN or public_ip()

def public_ip():
    global PUBLIC_IP_CACHE,PUBLIC_IP_CACHE_AT
    if PUBLIC_IP_CACHE and time.time()-PUBLIC_IP_CACHE_AT < 300:
        return PUBLIC_IP_CACHE
    try:
        value=subprocess.check_output(['curl','-4fsS','--max-time','3','https://api.ipify.org'],text=True).strip()
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',value):
            PUBLIC_IP_CACHE=value
    except Exception:
        pass
    if not PUBLIC_IP_CACHE:
        try:
            value=subprocess.check_output(['hostname','-I'],text=True).split()[0]
            if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',value):
                PUBLIC_IP_CACHE=value
        except Exception:
            pass
    return PUBLIC_IP_CACHE or '127.0.0.1'

def _primary_interface():
    global PRIMARY_INTERFACE,PRIMARY_INTERFACE_AT
    now=time.monotonic()
    if PRIMARY_INTERFACE and now-PRIMARY_INTERFACE_AT < 60:
        return PRIMARY_INTERFACE
    try:
        p=subprocess.run(['ip','route','show','default'],capture_output=True,text=True,timeout=3,check=False)
        for line in p.stdout.splitlines():
            parts=line.split()
            if 'dev' in parts:
                i=parts.index('dev')
                if i+1 < len(parts):
                    PRIMARY_INTERFACE=parts[i+1]
                    PRIMARY_INTERFACE_AT=now
                    return PRIMARY_INTERFACE
    except Exception:
        pass
    return PRIMARY_INTERFACE or ''

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

def service_state(name):
    return service_states([name]).get(name,'unknown')

def service_states(names):
    names=list(names)
    if not names:
        return {}
    try:
        p=subprocess.run(['systemctl','is-active',*names],capture_output=True,text=True,timeout=5,check=False)
        values=p.stdout.splitlines()
        if len(values)==len(names):
            return dict(zip(names,values))
    except Exception:
        pass
    out={}
    for name in names:
        try: out[name]=subprocess.check_output(['systemctl','is-active',name],stderr=subprocess.DEVNULL,text=True,timeout=3).strip()
        except Exception: out[name]='unknown'
    return out

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
        'uptime_seconds':int(float(open('/proc/uptime').read().split()[0])) if os.path.exists('/proc/uptime') else 0
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
                try:
                    with open(f'/proc/{pid}/status',encoding='utf-8') as fh:
                        uid_line=next((x for x in fh if x.startswith('Uid:')), '')
                    uid=int(uid_line.split()[1]) if uid_line else -1
                    if uid >= 0:
                        user=pwd.getpwuid(uid).pw_name
                except Exception:
                    pass
            out.append({'local':local,'remote':peer,'process':proc,'pid':pid,'user':user,'transport':'tcp'})
            if len(out)>=100: break
    except Exception:
        pass
    try:
        for user,count in _hysteria_online().items():
            if count>0:
                out.append({'local':'udp/:53','remote':'—','process':'hysteria','pid':None,'user':user,'transport':'udp','connections':count})
    except Exception:
        pass
    return out[:150]

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
        text=subprocess.check_output(['journalctl','-u','ssh','--since','24 hours ago','-n','5000','--no-pager'],text=True,stderr=subprocess.DEVNULL)
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
