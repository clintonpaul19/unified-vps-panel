import time
from .config import XRAY_TAGS,XRAY_LOCK
from .db import conn
from .hysteria import _hysteria_usage,kick_hysteria
from .ssh import set_ssh_enabled
from .xray import del_xray,load_xray,save_xray,_xray_usage

# Keep usage synchronization as a dedicated worker so HTTP handlers never own this responsibility.
def sync_usage():
    while True:
        try:
            xusage=_xray_usage()
            husage=_hysteria_usage()
            c=conn()
            rows=c.execute('select id,username,protocol,raw_bytes,used_bytes,daily_used_bytes,usage_day,expiry,quota_bytes,enabled from users').fetchall()
            now=int(time.time())
            today=time.strftime('%Y-%m-%d',time.localtime(now))
            disable=[]
            updates=[]
            for row in rows:
                expired=bool(row['expiry'] and row['expiry']<=now)
                prev=int(row['raw_bytes'] or 0)
                protocol=row['protocol']
                if protocol in XRAY_TAGS:
                    if xusage is None:
                        if row['enabled'] and expired: disable.append(row)
                        continue
                    raw=int(xusage.get(row['username'],prev))
                elif protocol=='Hysteria':
                    if husage is None:
                        if row['enabled'] and expired: disable.append(row)
                        continue
                    raw=int(husage.get(row['username'],prev))
                else:
                    if row['enabled'] and expired: disable.append(row)
                    continue
                delta=raw-prev if raw >= prev else raw
                used=int(row['used_bytes'] or 0)+delta
                daily=int(row['daily_used_bytes'] or 0)
                usage_day=row['usage_day'] or ''
                if usage_day != today:
                    daily=0
                daily += delta
                quota_hit=bool(row['quota_bytes'] and used>=row['quota_bytes'])
                if row['enabled'] and (expired or quota_hit):
                    disable.append(row)
                if raw != prev or usage_day != today or delta:
                    updates.append((used,raw,daily,today,row['id']))
            if updates:
                c.executemany('update users set used_bytes=?,raw_bytes=?,daily_used_bytes=?,usage_day=? where id=?',updates)

            rx,tx=_server_bytes()
            srv=c.execute('select raw_rx,raw_tx,all_time_bytes,daily_bytes,usage_day from server_usage where id=1').fetchone()
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
            c.commit()
            c.close()

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

            if disable:
                c=conn()
                event_rows=[]
                for row in disable:
                    event_rows.append((now,'account_auto_disabled',row['username'],'expired or quota reached'))
                    if row['protocol']=='Hysteria':
                        kick_hysteria(row['username'])
                    if row['protocol']=='SSH':
                        try: set_ssh_enabled(row['username'],False)
                        except Exception: pass
                c.executemany('insert into events(created_at,action,username,details) values(?,?,?,?)',event_rows)
                c.executemany('update users set enabled=0 where id=?',[(row['id'],) for row in disable])
                c.commit(); c.close()
        except Exception:
            pass
        time.sleep(15)
