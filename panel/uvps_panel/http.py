import html
import hmac
import json
import os
import re
import subprocess
import tarfile
import threading
import time
from urllib.parse import parse_qs,urlsplit
from http.server import BaseHTTPRequestHandler

from .accounts import apply_user_action,create_user,record
from .auth import _request_token,_save_admin_credentials,_session_cookie,_valid_request_token,admin_configured,auth,verify_admin_credentials
from .config import MAINT_LOCK,PANEL_BUILD,PORT,SETUP_LOCK,SPEEDTEST_LOCK
from .db import conn,log_event
from .hysteria import _hysteria_online,kick_hysteria
from .http_utils import body,redirect,send,send_html
from .system import _active_sessions,_certificate_info,_security_info,_system_metrics,public_host,service_states
from .views import dashboard_page,login_page,setup_page
from .cache import cached_value

class H(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def do_GET(self):
        parsed=urlsplit(self.path)
        self.path=parsed.path
        self.query=parsed.query
        if self.path=='/health':
            if self.client_address[0] not in ('127.0.0.1','::1'):
                return send(self,{'ok':True,'service':'unified-vps-panel'})
            service_names=('ssh','nginx','haproxy','xray','hysteria-server','unified-vps-wstunnel-ssh','unified-vps-ws-payload-ssh','unified-vps-panel')
            services=service_states(service_names)
            wanted={22,80,143,443,8080,8443,8880,6080}
            tcp={str(port):False for port in wanted}
            try:
                out=subprocess.run(['ss','-lntH'],capture_output=True,text=True,timeout=3,check=False)
                for line in out.stdout.splitlines():
                    parts=line.split()
                    if len(parts)>=4:
                        try:
                            port=int(parts[3].rsplit(':',1)[1])
                            if port in wanted:
                                tcp[str(port)]=True
                        except (ValueError,IndexError):
                            pass
            except Exception:
                pass
            try:
                out=subprocess.run(['ss','-lunH'],capture_output=True,text=True,timeout=3,check=False)
                udp53=False
                for line in out.stdout.splitlines():
                    parts=line.split()
                    if len(parts)>=4:
                        try:
                            if int(parts[3].rsplit(':',1)[1])==53:
                                udp53=True
                                break
                        except (ValueError,IndexError):
                            pass
            except Exception:
                udp53=False
            return send(self,{'ok':True,'services':services,'listeners':{'tcp':tcp,'udp53':udp53}})
        if not admin_configured():
            if self.path in ('/','/setup'): return setup_page(self)
            return send(self,{'error':'panel setup required'},503)
        if self.path=='/login' and not auth(self.headers,self.client_address[0] in ('127.0.0.1','::1')): return login_page(self)
        if not auth(self.headers,self.client_address[0] in ('127.0.0.1','::1')):
            if self.path.startswith('/api/'):
                return send(self,{'error':'authentication required'},401)
            return login_page(self)
            self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="Unified VPS"'); self.end_headers(); return

        if self.path=='/api/users/secret':
            try:
                values=parse_qs(getattr(self,'query',''),keep_blank_values=False)
                uid=int(values.get('id',['0'])[0])
            except (TypeError,ValueError):
                return send(self,{'error':'invalid id'},400)
            c=conn()
            row=c.execute('select * from users where id=?',(uid,)).fetchone()
            c.close()
            if not row:
                return send(self,{'error':'not found'},404)
            return send(self,record(row))

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
            rows=c.execute('select id,username,protocol,used_bytes,daily_used_bytes,quota_bytes,usage_day,expiry from users order by id desc').fetchall()
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
                        'usage_day':r['usage_day'] or '',
                        'days_remaining':None if not r['expiry'] else max(int((r['expiry']-int(time.time()))/86400),0),
                        'expiry_warning':bool(r['expiry'] and r['expiry']<=int(time.time())+7*86400)
                    } for r in rows
                ]
            }
            return send(self,data)
        if self.path=='/api/metrics':
            return send(self,cached_value('metrics',2.0,_system_metrics))

        if self.path=='/api/sessions':
            return send(self,{'updated_at':int(time.time()),'sessions':cached_value('sessions',2.0,_active_sessions)})

        if self.path=='/api/security':
            info=cached_value('security',30.0,_security_info)
            info=dict(info); info['certificate']=cached_value('certificate',60.0,_certificate_info)
            return send(self,info)

        if self.path=='/api/certificate':
            return send(self,cached_value('certificate',60.0,_certificate_info))

        if self.path=='/api/events':
            c=conn()
            rows=c.execute('select id,created_at,action,username,details from events order by id desc limit 100').fetchall()
            c.close()
            return send(self,{'events':[dict(x) for x in rows]})

        if self.path=='/api/backup':
            def list_backups():
                files=[]
                for path in sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)[:10]:
                    try:
                        files.append({'name':os.path.basename(path),'size':os.path.getsize(path),'created_at':int(os.path.getmtime(path))})
                    except OSError: pass
                return {'backups':files}
            return send(self,cached_value('backups',10.0,list_backups))

        if self.path=='/api/speedtest':
            if not SPEEDTEST_LOCK.acquire(blocking=False):
                return send(self,{'ok':False,'output':'Speedtest already running'},409)
            try:
                env=os.environ.copy()
                env.update({'HOME':'/root','USER':'root','LOGNAME':'root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'})
                p=subprocess.run(['speedtest','--accept-license','--accept-gdpr'],capture_output=True,text=True,timeout=180,env=env)
                output=(p.stdout or p.stderr).strip()
                if p.returncode != 0 and not output:
                    output=f'Speedtest exited with code {p.returncode}'
                return send(self,{'ok':p.returncode==0,'output':output},200 if p.returncode==0 else 500)
            except Exception as e: return send(self,{'ok':False,'output':str(e)},500)
            finally:
                SPEEDTEST_LOCK.release()
        if self.path=='/':
            return send_html(self,dashboard_page())
        self.send_response(404)
        self.send_header('Content-Length','0')
        self.end_headers(); return

    def do_POST(self):
        self.path=urlsplit(self.path).path
        if self.path=='/setup':
            try:
                d=body(self)
            except Exception as e:
                return send(self,{'error':str(e) or 'invalid request body'},400)
            with SETUP_LOCK:
                if admin_configured(): return send(self,{'error':'panel is already configured'},409)
                token=str(d.get('setup_token',''))
                if not token or not _valid_request_token('setup',token): return send(self,{'error':'invalid setup request'},403)
                u=str(d.get('username','')).strip()
                p=str(d.get('password',''))
                confirm=str(d.get('confirm',''))
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{2,31}',u):
                    return send(self,{'error':'Username must be 3-32 characters using letters, numbers, dot, underscore or hyphen.'},400)
                if len(p)<8 or len(p)>128 or '\n' in p or '\r' in p:
                    return send(self,{'error':'Password must be 8-128 characters and cannot contain newlines.'},400)
                if p!=confirm: return send(self,{'error':'Passwords do not match.'},400)
                try:
                    _save_admin_credentials(u,p)
                    log_event('panel_setup',details='Initial administrator account created')
                except Exception as e:
                    return send(self,{'error':'Could not save administrator credentials: '+str(e)},500)
                return redirect(self,'/',303,{'Set-Cookie':f'{SESSION_COOKIE}={_session_cookie(u)}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}'})
        if self.path=='/login':
            try: d=body(self)
            except Exception: return send(self,{'error':'invalid JSON'},400)
            if not admin_configured(): return send(self,{'error':'panel setup required'},503)
            token=str(d.get('login_token',''))
            if not token or not _valid_request_token('login',token): return send(self,{'error':'invalid login request'},403)
            client_ip=self.client_address[0]; now=time.time()
            with LOGIN_LOCK:
                state=LOGIN_FAILURES.get(client_ip,[0,now])
                if now-state[1] > LOGIN_WINDOW: state=[0,now]
                if state[0] >= LOGIN_MAX_FAILURES:
                    retry=max(1,int(LOGIN_WINDOW-(now-state[1])))
                    return send(self,{'error':'too many login attempts; try again later'},429,{'Retry-After':str(retry)})
            u=str(d.get('username','')); p=str(d.get('password',''))
            if verify_admin_credentials(u,p):
                with LOGIN_LOCK: LOGIN_FAILURES.pop(client_ip,None)
                return redirect(self,'/',303,{'Set-Cookie':f'{SESSION_COOKIE}={_session_cookie(u)}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}'})
            with LOGIN_LOCK:
                stale=[ip for ip,state in LOGIN_FAILURES.items() if now-state[1] > LOGIN_WINDOW]
                for ip in stale: LOGIN_FAILURES.pop(ip,None)
                state=LOGIN_FAILURES.get(client_ip,[0,now])
                if now-state[1] > LOGIN_WINDOW: state=[0,now]
                state[0]+=1; LOGIN_FAILURES[client_ip]=state
                if len(LOGIN_FAILURES)>10000:
                    oldest=sorted(LOGIN_FAILURES.items(),key=lambda item:item[1][1])[:1000]
                    for ip,_ in oldest: LOGIN_FAILURES.pop(ip,None)
            return send(self,{'error':'invalid credentials'},401)
        if self.path=='/hysteria-auth':
            if self.client_address[0] not in ('127.0.0.1','::1'):
                return send(self,{'ok':False},403)
            try: d=body(self)
            except Exception: return send(self,{'ok':False},400)
            secret=str(d.get('auth','')); c=conn()
            r=c.execute('select username,expiry,enabled from users where protocol="Hysteria" and secret=?',(secret,)).fetchone(); c.close()
            if not r or not r['enabled'] or (r['expiry'] and r['expiry']<=int(time.time())): return send(self,{'ok':False})
            return send(self,{'ok':True,'id':r['username']})
        if not auth(self.headers,self.client_address[0] in ('127.0.0.1','::1')):
            self.send_response(401)
            self.send_header('Content-Length','0')
            self.end_headers(); return
        try: d=body(self)
        except Exception: return send(self,{'error':'invalid JSON'},400)
        if self.path=='/api/backup':
            with MAINT_LOCK:
                action=str(d.get('action','')).lower()
                if action=='create':
                    try:
                        p=subprocess.run(['/usr/local/sbin/unified-vps-backup'],capture_output=True,text=True,timeout=120)
                        if p.returncode:
                            return send(self,{'error':(p.stderr or p.stdout).strip() or 'backup failed'},500)
                        path=p.stdout.strip()
                        if not path or not os.path.isfile(path):
                            return send(self,{'error':'backup command did not produce a valid archive'},500)
                        log_event('backup_created',os.path.basename(path),'')
                        return send(self,{'ok':True,'path':path})
                    except subprocess.TimeoutExpired:
                        return send(self,{'error':'backup timed out'},504)
                    except Exception as e:
                        return send(self,{'error':str(e)},500)
                if action=='restore':
                    files=sorted(__import__('glob').glob('/opt/unified-vps/backups/unified-vps-*.tar.gz'),reverse=True)
                    if not files:
                        return send(self,{'error':'no backup available'},404)
                    latest=files[0]
                    test=subprocess.run(['tar','-tzf',latest],capture_output=True,text=True,timeout=30)
                    if test.returncode:
                        return send(self,{'error':'latest backup is invalid'},500)
                    try:
                        with tarfile.open(latest,'r:gz') as tf:
                            for member in tf.getmembers():
                                name=os.path.normpath(member.name)
                                if name.startswith('/') or name == '..' or name.startswith('../'):
                                    return send(self,{'error':'backup contains an unsafe path'},400)
                        p=subprocess.run(['tar','-xzf',latest,'-C','/'],capture_output=True,text=True,timeout=120)
                        if p.returncode:
                            return send(self,{'error':(p.stderr or p.stdout).strip() or 'restore failed'},500)
                        log_event('backup_restored',os.path.basename(latest),'')
                        result=send(self,{'ok':True,'path':latest,'message':'Restore applied; services will restart shortly.'})
                        def restart_restored_services():
                            subprocess.run(['systemctl','daemon-reload'],capture_output=True)
                            if os.path.exists('/etc/iptables/rules.v4'):
                                with open('/etc/iptables/rules.v4','rb') as fh:
                                    subprocess.run(['iptables-restore'],stdin=fh,capture_output=True)
                            subprocess.run(['systemctl','restart','fail2ban'],capture_output=True)
                            subprocess.run(['systemctl','restart','nginx','xray','hysteria-server','haproxy','unified-vps-panel','unified-vps-wstunnel-ssh','unified-vps-ws-payload-ssh'],capture_output=True)
                            subprocess.run(['systemctl','restart','unified-vps-watchdog.timer','unified-vps-backup.timer'],capture_output=True)
                        threading.Timer(2.0,restart_restored_services).start()
                        return result
                    except subprocess.TimeoutExpired:
                        return send(self,{'error':'restore timed out'},504)
                    except Exception as e:
                        return send(self,{'error':str(e)},500)
                return send(self,{'error':'unsupported backup action'},400)

        if self.path=='/api/certificate/renew':
            with MAINT_LOCK:
                try:
                    acme='/root/.acme.sh/acme.sh'
                    if not os.path.exists(acme):
                        return send(self,{'error':'acme.sh not installed'},500)
                    was_active=subprocess.run(['systemctl','is-active','--quiet','haproxy'],check=False).returncode==0
                    args=[acme,'--renew','-d',public_host(),'--force']
                    if was_active:
                        args += ['--pre-hook','systemctl stop haproxy','--post-hook','systemctl start haproxy']
                    p=subprocess.run(args,capture_output=True,text=True,timeout=180)
                    if p.returncode:
                        return send(self,{'error':(p.stderr or p.stdout).strip() or 'certificate renewal failed'},500)
                    log_event('certificate_renewed',public_host(),'')
                    return send(self,{'ok':True,'output':(p.stdout or '').strip()})
                except subprocess.TimeoutExpired:
                    return send(self,{'error':'certificate renewal timed out'},504)
                except Exception as e:
                    return send(self,{'error':str(e)},500)
                finally:
                    if 'was_active' in locals() and was_active:
                        subprocess.run(['systemctl','start','haproxy'],capture_output=True)

        if self.path=='/api/users':
            try: return send(self,create_user(d))
            except Exception as e: return send(self,{'error':str(e)},500)
        if self.path=='/api/users/bulk':
            ids=[int(x) for x in d.get('ids',[]) if str(x).isdigit()][:5000]
            action=str(d.get('action','')).lower()
            if not ids or action not in ('enable','disable','delete','renew'):
                return send(self,{'error':'invalid bulk request'},400)
            days=int(d.get('days',0) or 0)
            if action=='renew' and days<=0:
                return send(self,{'error':'renewal days required'},400)
            results=[]
            for uid in ids:
                try:
                    apply_user_action(uid,action,days,event_name='bulk_'+action)
                    results.append({'id':uid,'ok':True})
                except KeyError:
                    results.append({'id':uid,'ok':False,'error':'not found'})
                except Exception as e:
                    results.append({'id':uid,'ok':False,'error':str(e)})
            return send(self,{'ok':all(x['ok'] for x in results),'results':results})

        if self.path=='/api/users/action':
            uid=d.get('id',0)
            try: uid=int(uid)
            except (TypeError,ValueError): return send(self,{'error':'invalid id'},400)
            action=str(d.get('action','')).lower()
            if action not in ('enable','disable','renew'):
                return send(self,{'error':'unsupported action'},400)
            try:
                days=int(d.get('days',0) or 0)
                apply_user_action(uid,action,days)
                return send(self,{'ok':True,'action':action,'id':uid})
            except KeyError:
                return send(self,{'error':'not found'},404)
            except Exception as e:
                return send(self,{'error':str(e)},500)

        if self.path=='/api/users/delete':
            try:
                uid=int(d.get('id',0))
            except (TypeError,ValueError):
                return send(self,{'error':'invalid id'},400)
            try:
                apply_user_action(uid,'delete')
                return send(self,{'ok':True})
            except KeyError:
                return send(self,{'error':'not found'},404)
            except Exception as e:
                return send(self,{'error':str(e)},500)
        return send(self,{'error':'not found'},404)
