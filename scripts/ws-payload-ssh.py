#!/usr/bin/env python3
import base64
import hashlib
import select
import socket
import sys
import threading
import time

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18447
SSH_TARGET = ("127.0.0.1", 22)
MAX_HEADER = 64 * 1024
READ_TIMEOUT = 8.0
IDLE_TIMEOUT = 3600.0


def recv_headers(conn):
    conn.settimeout(READ_TIMEOUT)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > MAX_HEADER:
            raise ValueError("headers too large")
    head, rest = data.split(b"\r\n\r\n", 1)
    return head.decode("iso-8859-1"), rest


def parse_request(head):
    lines = head.split("\r\n")
    if not lines or len(lines[0].split()) != 3:
        raise ValueError("bad request line")
    method, path, version = lines[0].split()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, path, version, headers


def send_http(conn, status, body=b"Unified VPS"):
    reason = {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        405: "Method Not Allowed",
        502: "Bad Gateway",
    }.get(status, "Error")
    response = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body
    conn.sendall(response)


def websocket_accept(key):
    magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1(key.encode() + magic).digest()).decode()


def recv_exact(conn, n):
    out = b""
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            return None
        out += chunk
    return out


def websocket_to_ssh(client, ssh, initial):
    buf = initial
    client.settimeout(IDLE_TIMEOUT)
    ssh.settimeout(IDLE_TIMEOUT)

    while True:
        if not buf:
            buf = client.recv(65536)
            if not buf:
                return

        while buf:
            if len(buf) < 2:
                more = client.recv(4096)
                if not more:
                    return
                buf += more
                continue

            b1, b2 = buf[0], buf[1]
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            pos = 2

            if length == 126:
                if len(buf) < pos + 2:
                    buf += client.recv(4096)
                    continue
                length = int.from_bytes(buf[pos:pos + 2], "big")
                pos += 2
            elif length == 127:
                if len(buf) < pos + 8:
                    buf += client.recv(4096)
                    continue
                length = int.from_bytes(buf[pos:pos + 8], "big")
                pos += 8

            if length > 16 * 1024 * 1024:
                return

            mask = b""
            if masked:
                if len(buf) < pos + 4:
                    buf += client.recv(4096)
                    continue
                mask = buf[pos:pos + 4]
                pos += 4

            if len(buf) < pos + length:
                more = client.recv(min(65536, pos + length - len(buf)))
                if not more:
                    return
                buf += more
                continue

            payload = buf[pos:pos + length]
            buf = buf[pos + length:]

            if masked:
                payload = bytes(v ^ mask[i % 4] for i, v in enumerate(payload))

            if opcode == 0x8:
                try:
                    client.sendall(b"\x88\x00")
                except OSError:
                    pass
                return
            if opcode == 0x9:
                client.sendall(b"\x8a" + bytes([len(payload)]) + payload)
                continue
            if opcode == 0xA:
                continue
            if opcode not in (0x0, 0x1, 0x2):
                continue

            if payload:
                ssh.sendall(payload)

            # Fragmentation is uncommon for tunnel payloads. For fragmented
            # messages, continuation frames (opcode 0) are handled identically.


def ssh_to_websocket(client, ssh):
    while True:
        data = ssh.recv(65536)
        if not data:
            return
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + 65535]
            pos += len(chunk)
            header = b"\x82"
            if len(chunk) < 126:
                header += bytes([len(chunk)])
            elif len(chunk) <= 65535:
                header += b"\x7e" + len(chunk).to_bytes(2, "big")
            else:
                header += b"\x7f" + len(chunk).to_bytes(8, "big")
            client.sendall(header + chunk)


def raw_to_ssh(client, ssh, initial):
    sockets = [client, ssh]
    if initial:
        ssh.sendall(initial)
    client.settimeout(IDLE_TIMEOUT)
    ssh.settimeout(IDLE_TIMEOUT)

    while True:
        readable, _, _ = select.select(sockets, [], [], IDLE_TIMEOUT)
        if not readable:
            return
        for src in readable:
            data = src.recv(65536)
            if not data:
                return
            dst = ssh if src is client else client
            dst.sendall(data)


def handle(conn, addr):
    ssh = None
    try:
        parsed = recv_headers(conn)
        if parsed is None:
            return
        head, initial = parsed
        method, path, version, headers = parse_request(head)

        if method != "GET" or version != "HTTP/1.1":
            send_http(conn, 405, b"Method Not Allowed\n")
            return

        upgrade = headers.get("upgrade", "").lower() == "websocket"
        # Legacy tunnel clients may send only Upgrade: websocket and omit
        # Connection: Upgrade. Accept that documented payload form.
        if not upgrade:
            send_http(conn, 200, b"Unified VPS\n")
            return

        key = headers.get("sec-websocket-key")
        if key:
            accept = websocket_accept(key)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "\r\n"
            ).encode()
            conn.sendall(response)
            websocket_mode = True
        else:
            # Legacy payload compatibility: accept the minimal Upgrade request
            # used by tunnel clients that omit Sec-WebSocket-Key.
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"\r\n"
            )
            websocket_mode = False

        ssh = socket.create_connection(SSH_TARGET, timeout=READ_TIMEOUT)

        if websocket_mode:
            t = threading.Thread(target=ssh_to_websocket, args=(conn, ssh), daemon=True)
            t.start()
            websocket_to_ssh(conn, ssh, initial)
            return

        raw_to_ssh(conn, ssh, initial)
    except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError, ValueError):
        try:
            if conn:
                send_http(conn, 400, b"Bad Request\n")
        except Exception:
            pass
    finally:
        for s in (ssh, conn):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(128)
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
