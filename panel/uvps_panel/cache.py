import threading
import time

CACHE_LOCK=threading.Lock()
CACHE_VALUES={}
CACHE_INFLIGHT={}

def cached_value(key,ttl,fn):
    now=time.monotonic()
    with CACHE_LOCK:
        item=CACHE_VALUES.get(key)
        if item and now-item[0] < ttl:
            return item[1]
        event=CACHE_INFLIGHT.get(key)
        if event is None:
            event=threading.Event()
            CACHE_INFLIGHT[key]=event
            owner=True
        else:
            owner=False
    if not owner:
        event.wait(timeout=max(ttl,1.0)+5.0)
        with CACHE_LOCK:
            item=CACHE_VALUES.get(key)
            if item and time.monotonic()-item[0] < ttl:
                return item[1]
        return fn()
    try:
        value=fn()
        with CACHE_LOCK:
            CACHE_VALUES[key]=(time.monotonic(),value)
        return value
    finally:
        with CACHE_LOCK:
            CACHE_INFLIGHT.pop(key,None)
            event.set()
