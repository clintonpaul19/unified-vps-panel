import os
import sqlite3
import threading
import time
from .config import BASE,DB

DB_INIT_LOCK=threading.Lock()
DB_INITIALIZED=False

def init_db():
    global DB_INITIALIZED
    if DB_INITIALIZED:
        return
    with DB_INIT_LOCK:
        if DB_INITIALIZED:
            return
        os.makedirs(BASE, exist_ok=True, mode=0o700)
        os.chmod(BASE, 0o700)
        c=sqlite3.connect(DB, timeout=5)
        try:
            os.chmod(DB, 0o600)
        except OSError:
            pass
        try:
            c.execute('pragma journal_mode=WAL')
            c.execute('pragma synchronous=NORMAL')
            c.execute('pragma busy_timeout=5000')
            c.execute('pragma foreign_keys=ON')
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
            c.execute('create index if not exists idx_users_protocol on users(protocol)')
            c.execute('create index if not exists idx_users_expiry on users(expiry)')
            c.execute('create index if not exists idx_events_created on events(created_at desc)')
            c.execute('insert or ignore into server_usage(id,raw_rx,raw_tx,all_time_bytes,daily_bytes,usage_day) values(1,0,0,0,0,?)',
                      (time.strftime('%Y-%m-%d'),))
            c.commit()
            DB_INITIALIZED=True
        finally:
            c.close()

def conn():
    init_db()
    c=sqlite3.connect(DB, timeout=5)
    try:
        os.chmod(BASE, 0o700)
        os.chmod(DB, 0o600)
    except OSError:
        pass
    c.row_factory=sqlite3.Row
    c.execute('pragma busy_timeout=5000')
    c.execute('pragma foreign_keys=ON')
    return c

def log_event(action, details='', username=''):
    global EVENT_PRUNE_COUNTER
    try:
        c=conn()
        c.execute('insert into events(created_at,action,username,details) values(?,?,?,?)',
                  (int(time.time()),str(action),str(username),str(details)))
        with EVENT_PRUNE_LOCK:
            EVENT_PRUNE_COUNTER += 1
            prune = EVENT_PRUNE_COUNTER >= 25
            if prune:
                EVENT_PRUNE_COUNTER = 0
        if prune:
            c.execute('delete from events where id not in (select id from events order by id desc limit 500)')
        c.commit(); c.close()
    except Exception:
        pass
