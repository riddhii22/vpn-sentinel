#!/usr/bin/env python3
"""Background listeners on client-b: HTTP, UDP VoIP-like, bulk TCP, fake SMTP."""

from __future__ import annotations

import socket
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


def _udp_sink(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        sock.recvfrom(2048)


def _tcp_sink(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(8)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=_drain, args=(conn,), daemon=True).start()


def _drain(conn: socket.socket) -> None:
    try:
        while conn.recv(65536):
            pass
    finally:
        conn.close()


def _smtp_sink(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(8)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=_smtp_session, args=(conn,), daemon=True).start()


def _smtp_session(conn: socket.socket) -> None:
    try:
        conn.sendall(b"220 vpn-sentinel.lab lab SMTP\r\n")
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                cmd = line[:4].upper()
                if cmd == b"DATA":
                    conn.sendall(b"354 go\r\n")
                elif cmd == b"QUIT":
                    conn.sendall(b"221 bye\r\n")
                    return
                else:
                    conn.sendall(b"250 ok\r\n")
    finally:
        conn.close()


def main() -> None:
    threading.Thread(target=_udp_sink, args=(5004,), daemon=True).start()
    threading.Thread(target=_tcp_sink, args=(9100,), daemon=True).start()
    threading.Thread(target=_smtp_sink, args=(2525,), daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", 8080), SimpleHTTPRequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
