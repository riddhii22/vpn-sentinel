#!/usr/bin/env python3
"""Generate lab inner traffic from client-a toward client-b."""

from __future__ import annotations

import argparse
import socket
import time
import urllib.request


def web(host: str) -> None:
    for path in ("/small.bin", "/page.html", "/"):
        urllib.request.urlopen(f"http://{host}:8080{path}", timeout=5).read()


def voip(host: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\x80" + b"\x00" * 159
    deadline = time.time() + 2.0
    while time.time() < deadline:
        sock.sendto(payload, (host, 5004))
        time.sleep(0.02)


def bulk(host: str) -> None:
    blob = b"B" * 65536
    with socket.create_connection((host, 9100), timeout=8) as sock:
        for _ in range(8):
            sock.sendall(blob)


def email(host: str) -> None:
    with socket.create_connection((host, 2525), timeout=8) as sock:
        sock.recv(256)
        for line in (
            b"EHLO client-a.lab\r\n",
            b"MAIL FROM:<lab@vpn-sentinel.lab>\r\n",
            b"RCPT TO:<sink@vpn-sentinel.lab>\r\n",
            b"DATA\r\n",
        ):
            sock.sendall(line)
            sock.recv(256)
        sock.sendall(b"Subject: lab\r\n\r\nhello from vpn sentinel lab\r\n.\r\n")
        sock.recv(256)
        sock.sendall(b"QUIT\r\n")
        sock.recv(256)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("web", "voip", "bulk", "email"))
    parser.add_argument("--host", default="10.2.0.10")
    args = parser.parse_args()
    {"web": web, "voip": voip, "bulk": bulk, "email": email}[args.kind](args.host)


if __name__ == "__main__":
    main()
