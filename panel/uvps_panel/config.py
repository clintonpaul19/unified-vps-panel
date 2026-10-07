import os
import threading

BASE='/etc/unified-vps'
DB=f'{BASE}/panel.db'
CFG='/usr/local/etc/xray/config.json'
PORT=int(os.environ.get('PANEL_PORT','6080'))
PANEL_BUILD='2026-09-30.3'
DOMAIN=os.environ.get('SERVER_DOMAIN','')
PANEL_ENV=f'{BASE}/panel.env'
ADMIN_FILE=f'{BASE}/admin.json'
SESSION_COOKIE='uvps_session'
SESSION_TTL=12*60*60
LOGIN_WINDOW=600
LOGIN_MAX_FAILURES=8
HY2_STATS_SECRET=os.environ.get('HY2_STATS_SECRET','')
XRAY_TAGS={'VLESS':['vless443'],'VMess':['vmess443'],'Trojan':['trojan443']}
SSH_PORTS=[80,443,143,8080,8443,8880]
MAX_REQUEST_BODY=64*1024
SETUP_LOCK=threading.Lock()
LOGIN_LOCK=threading.Lock()
LOGIN_FAILURES={}
XRAY_LOCK=threading.RLock()
MAINT_LOCK=threading.Lock()
SPEEDTEST_LOCK=threading.Lock()
