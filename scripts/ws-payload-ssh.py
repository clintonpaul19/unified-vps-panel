#!/usr/bin/env python3
import base64
import hashlib
import select
import socket
import threading

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18447
SSH_TARGET = ("127.0.0.1", 22)
MAX_HEADER = 128 * 1024
READ_TIMEOUT = 8.0
IDLE_TIMEOUT = 3600.0


def recv_initial(conn):
    conn.settimeout(READ_TIMEOUT)
    first = conn.recv(4096)
    if not first:
        return None, None

    # Raw SSH starts with an SSH identification string and does not use HTTP
    # headers. Keep it fully transparent for clients using raw TCP on port 80.
    if first.startswith(b"SSH-"):
        return "raw", first

    data = first
    delimiter = None
    while True:
        if b"\r\n\r\n" in data:
            delimiter = b"\r\n\r\n"
            break
        if b"\n\n" in data:
            delimiter = b"\n\n"
            break
        if len(data) >= MAX_HEADER:
            raise ValueError("payload headers too large")
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            # Some custom tunnel clients send a header block without the
            # conventional terminator. Treat what arrived as a payload rather
            # than manufacturing an HTTP 400 response.
            return "opaque", data
        if not chunk:
            return "opaque", data
        data += chunk

    head, rest = data.split(delimiter, 1)
    return "http", (head.decode("iso-8859-1", "replace"), rest)


def parse_request(head):
    lines = [x for x in head.replace("\r\n", "\n").split("\n") if x]
    if not lines:
        return "GET", "/", "HTTP/1.1", {}

    parts = lines[0].split()
    if len(parts) >= 3:
        method, path, version = parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        method, path, version = parts[0], parts[1], "HTTP/1.1"
    else:
        method, path, version = "GET", "/", "HTTP/1.1"

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method.upper(), path, version.upper(), headers


def send_http(conn, status=200, body=b"Unified VPS\n"):
    reason = {
        200: "OK",
        101: "Switching Protocols",
        502: "Bad Gateway",
    }.get(status, "OK")
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
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F
            pos = 2

            if length == 126:
                if len(buf) < pos + 2:
                    more = client.recv(4096)
                    if not more:
                        return
                    buf += more
                    continue
                length = int.from_bytes(buf[pos:pos + 2], "big")
                pos += 2
            elif length == 127:
                if len(buf) < pos + 8:
                    more = client.recv(4096)
                    if not more:
                        return
                    buf += more
                    continue
                length = int.from_bytes(buf[pos:pos + 8], "big")
                pos += 8

            if length > 16 * 1024 * 1024:
                return

            mask = b""
            if masked:
                if len(buf) < pos + 4:
                    more = client.recv(4096)
                    if not more:
                        return
                    buf += more
                    continue
                mask = buf[pos:pos + 4]
                pos += 4

            while len(buf) < pos + length:
                more = client.recv(min(65536, pos + length - len(buf)))
                if not more:
                    return
                buf += more

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
                reply_len = len(payload)
                if reply_len < 126:
                    client.sendall(b"\x8a" + bytes([reply_len]) + payload)
                else:
                    client.sendall(b"\x8a\x7e" + reply_len.to_bytes(2, "big") + payload)
                continue
            if opcode == 0xA:
                continue
            if opcode not in (0x0, 0x1, 0x2):
                continue

            if payload:
                ssh.sendall(payload)


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
        kind, data = recv_initial(conn)
        if kind is None:
            return

        if kind in ("raw", "opaque"):
            # Opaque payloads are treated as a raw SSH transport. This keeps
            # port 80 from rejecting non-standard clients at either HAProxy or
            # this bridge. HTTP-style payloads receive a normal response below.
            if kind == "raw":
                ssh = socket.create_connection(SSH_TARGET, timeout=READ_TIMEOUT)
                raw_to_ssh(conn, ssh, data)
                return
            try:
                # Connect to SSH before sending 101. A failed backend connection
                # must not result in an invalid 101-then-502 response sequence.
                ssh = socket.create_connection(SSH_TARGET, timeout=READ_TIMEOUT)
                conn.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Upgrade: websocket\r\n"
                    b"\r\n"
                )
                raw_to_ssh(conn, ssh, data)
            except OSError:
                send_http(conn, 502, b"SSH backend unavailable\n")
            return

        head, initial = data
        method, path, version, headers = parse_request(head)

        upgrade = (
            "websocket" in headers.get("upgrade", "").lower()
            or bool(headers.get("sec-websocket-key"))
            or "upgrade" in headers.get("connection", "").lower()
        )

        if not upgrade:
            # Never reject unusual HTTP payloads with 400/405. Return a simple
            # 200 response for probes and ordinary HTTP requests.
            send_http(conn, 200, b"Unified VPS\n")
            return

        key = headers.get("sec-websocket-key")
        # Open the SSH backend before acknowledging the WebSocket upgrade.
        # Otherwise a backend failure would require sending a second HTTP
        # response after a 101, which is protocol-invalid.
        ssh = socket.create_connection(SSH_TARGET, timeout=READ_TIMEOUT)

        if key:
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                + f"Sec-WebSocket-Accept: {websocket_accept(key)}\r\n".encode()
                + b"\r\n"
            )
            websocket_mode = True
        else:
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"\r\n"
            )
            websocket_mode = False

        if websocket_mode:
            threading.Thread(target=ssh_to_websocket, args=(conn, ssh), daemon=True).start()
            websocket_to_ssh(conn, ssh, initial)
        else:
            raw_to_ssh(conn, ssh, initial)

    except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
        try:
            if conn:
                send_http(conn, 502, b"SSH backend unavailable\n")
        except Exception:
            pass
    except ValueError:
        try:
            # A malformed/non-standard payload should still not become HTTP 400.
            # Return a benign response rather than rejecting the connection.
            send_http(conn, 200, b"Unified VPS\n")
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
