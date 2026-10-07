import json
import gzip
import zlib
from urllib.parse import parse_qs
from .config import MAX_REQUEST_BODY,PANEL_BUILD

def _compress_response(r,b,headers):
    headers=headers or {}
    accept=(r.headers.get('Accept-Encoding','') or '').lower()
    if len(b)>=1024 and 'gzip' in accept:
        compressed=gzip.compress(b,compresslevel=5)
        if len(compressed)<len(b):
            b=compressed
            headers=dict(headers)
            headers['Content-Encoding']='gzip'
            headers['Vary']='Accept-Encoding'
    return b,headers

def send_html(r,body_html,status=200,headers=None):
    b=body_html.encode()
    b,headers=_compress_response(r,b,headers)
    r.send_response(status)
    r.send_header('Content-Type','text/html; charset=utf-8')
    r.send_header('Cache-Control','no-store')
    r.send_header('X-Content-Type-Options','nosniff')
    r.send_header('X-UVPS-Build',PANEL_BUILD)
    r.send_header('X-Frame-Options','DENY')
    r.send_header('Referrer-Policy','no-referrer')
    if headers:
        for k,v in headers.items(): r.send_header(k,v)
    r.send_header('Content-Length',str(len(b)))
    r.end_headers(); r.wfile.write(b)

def send(r,obj,status=200,headers=None):
    import json
    b=json.dumps(obj,separators=(',',':'),ensure_ascii=False).encode()
    b,headers=_compress_response(r,b,headers)
    r.send_response(status)
    r.send_header('Content-Type','application/json')
    r.send_header('Cache-Control','no-store')
    r.send_header('X-Content-Type-Options','nosniff')
    r.send_header('X-UVPS-Build',PANEL_BUILD)
    if headers:
        for k,v in headers.items(): r.send_header(k,v)
    r.send_header('Content-Length',str(len(b)))
    r.end_headers(); r.wfile.write(b)

def body(r):
    transfer=(r.headers.get('Transfer-Encoding','') or '').lower()
    if 'chunked' in transfer:
        chunks=[]; total=0
        while True:
            line=r.rfile.readline(128)
            if not line: raise ValueError('incomplete chunked request')
            try: size=int(line.split(b';',1)[0].strip(),16)
            except ValueError: raise ValueError('invalid chunk size')
            if size==0:
                while True:
                    trailer=r.rfile.readline(4096)
                    if not trailer or trailer in (b'\\r\\n',b'\\n'): break
                break
            total += size
            if total>MAX_REQUEST_BODY: raise ValueError('request body too large')
            chunk=r.rfile.read(size)
            if len(chunk)!=size: raise ValueError('incomplete request body')
            chunks.append(chunk)
            separator=r.rfile.read(2)
            if separator!=b'\\r\\n': raise ValueError('invalid chunk framing')
        raw=b''.join(chunks)
    else:
        try: length=int(r.headers.get('Content-Length','0') or 0)
        except (TypeError,ValueError): raise ValueError('invalid content length')
        if length<0 or length>MAX_REQUEST_BODY: raise ValueError('request body too large')
        raw=r.rfile.read(length)
        if len(raw)!=length: raise ValueError('incomplete request body')
    if not raw: return {}
    encoding=(r.headers.get('Content-Encoding','') or '').lower()
    if encoding in ('gzip','x-gzip'):
        try:
            dec=zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw=dec.decompress(raw,MAX_REQUEST_BODY+1)
            if len(raw)>MAX_REQUEST_BODY or dec.unconsumed_tail: raise ValueError('request body too large')
            raw += dec.flush(MAX_REQUEST_BODY+1-len(raw))
            if len(raw)>MAX_REQUEST_BODY: raise ValueError('request body too large')
        except (OSError,zlib.error):
            raise ValueError('invalid gzip request body')
    content_type=(r.headers.get('Content-Type','') or '').lower().split(';',1)[0].strip()
    try: decoded=raw.decode('utf-8')
    except UnicodeDecodeError: raise ValueError('request body is not valid UTF-8')
    if content_type in ('application/x-www-form-urlencoded','text/plain'):
        values=parse_qs(decoded,keep_blank_values=True)
        return {k:(v[-1] if v else '') for k,v in values.items()}
    try: value=json.loads(decoded)
    except json.JSONDecodeError: raise ValueError('invalid JSON')
    if not isinstance(value,dict): raise ValueError('request body must be a JSON object')
    return value
