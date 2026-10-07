import os
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer

from .config import PANEL_BUILD,PORT
from .db import init_db
from .http import H
from .telemetry import sync_usage

def main():
    init_db()
    if os.environ.get('PANEL_PREFLIGHT') != '1':
        threading.Thread(target=sync_usage,name='usage-sync',daemon=True).start()
    workers=max(4,min(int(os.environ.get('PANEL_MAX_WORKERS','32')),128))

    class BoundedHTTPServer(ThreadingHTTPServer):
        daemon_threads=True
        request_queue_size=128
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self._executor=ThreadPoolExecutor(max_workers=workers,thread_name_prefix='panel')
            self._slots=threading.BoundedSemaphore(workers+64)
        def process_request(self,request,client_address):
            if not self._slots.acquire(blocking=False):
                try: request.close()
                except OSError: pass
                return
            try:
                future=self._executor.submit(self.process_request_thread,request,client_address)
                future.add_done_callback(lambda _f:self._slots.release())
            except Exception:
                self._slots.release()
                try: request.close()
                except OSError: pass
        def server_close(self):
            try: self._executor.shutdown(wait=False,cancel_futures=True)
            finally: super().server_close()

    BoundedHTTPServer((os.environ.get('PANEL_BIND','0.0.0.0'),PORT),H).serve_forever()
