import subprocess
import time
from . import config

def sync_ssh_expiry(u,expiry):
    if expiry:
        exp_date=time.strftime('%Y-%m-%d',time.localtime(int(expiry)+86400))
        subprocess.run(['chage','-E',exp_date,u],check=False)
    else:
        subprocess.run(['chage','-E','-1',u],check=False)

def set_ssh_enabled(u,enabled,expiry=None):
    cmd=['usermod','-U' if enabled else '-L',u]
    p=subprocess.run(cmd,capture_output=True,text=True)
    if p.returncode: raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to change SSH account state')
    if enabled and expiry is not None: sync_ssh_expiry(u,expiry)
    if not enabled: subprocess.run(['pkill','-TERM','-u',u],capture_output=True)

def add_ssh(u,password,days):
    if subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError('Linux SSH username already exists')
    subprocess.run(['useradd','-m','-s','/bin/bash',u],check=True)
    p=subprocess.run(['chpasswd'],input=f'{u}:{password}\n',text=True,capture_output=True)
    if p.returncode:
        subprocess.run(['userdel','-r',u],capture_output=True)
        raise RuntimeError('Failed to set SSH password')
    subprocess.run(['usermod','-U',u],capture_output=True,check=False)
    sync_ssh_expiry(u,int(time.time())+days*86400 if days else 0)

def del_ssh(u):
    if subprocess.run(['id',u],capture_output=True).returncode != 0: return
    subprocess.run(['pkill','-TERM','-u',u],capture_output=True)
    p=subprocess.run(['userdel','-r',u],capture_output=True,text=True)
    if p.returncode and subprocess.run(['id',u],capture_output=True).returncode==0:
        raise RuntimeError((p.stderr or p.stdout).strip() or 'Failed to delete SSH account')
