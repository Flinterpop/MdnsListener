"""Bench feeder for MDNS Listener: sends a known number of mDNS packets to
224.0.0.251:5353 over the LOOPBACK interface only, so nothing reaches the
LAN, and the listener's count can be checked one-for-one.

    C:\\Python314\\python.exe tools\\feed_mdns.py --count 50

Each round is a two-host exchange: 127.0.0.1 asks for PTR _probe._tcp.local
(QU bit set) and 127.0.0.2 answers with PTR, SRV, TXT and A records for a
made-up instance, so the sequence chart has a query to match each response
to. With --malformed, 127.0.0.1 also sends one packet whose compression
pointer points forward.
"""

from __future__ import annotations

import argparse
import socket
import struct
import time

GROUP = "224.0.0.251"
PORT = 5353


def name(*labels: str) -> bytes:
    out = b""
    for label in labels:
        raw = label.encode("utf-8")
        assert 0 < len(raw) < 64
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def rr(owner: bytes, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def query(i: int) -> bytes:
    del i
    header = struct.pack("!6H", 0, 0x0000, 1, 0, 0, 0)
    return header + name("_probe", "_tcp", "local") + struct.pack("!HH", 12, 0x8001)


def response(i: int) -> bytes:
    header = struct.pack("!6H", 0, 0x8400, 0, 4, 0, 0)  # id, flags, QD, AN, NS, AR
    service = name("_probe", "_tcp", "local")
    instance = name(f"Probe {i}", "_probe", "_tcp", "local")
    host = name(f"probe-{i}", "local")
    body = rr(service, 12, 1, 4500, instance)
    body += rr(instance, 33, 0x8001, 120, struct.pack("!HHH", 0, 0, 9000 + i) + host)
    txt = b""
    for s in (f"round={i}".encode(), b"pw=0"):
        txt += bytes([len(s)]) + s
    body += rr(instance, 16, 0x8001, 4500, txt)
    body += rr(host, 1, 0x8001, 120, bytes([127, 0, 0, 2]))
    return header + body


def malformed() -> bytes:
    header = struct.pack("!6H", 0, 0, 1, 0, 0, 0)
    return header + b"\xc0\x20" + struct.pack("!HH", 1, 1)


def open_sender(address: str) -> socket.socket:
    """A socket that multicasts out the loopback interface from `address`."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("127.0.0.1"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.bind((address, 0))
    return sock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10, help="rounds to send (1..10000)")
    parser.add_argument("--malformed", action="store_true", help="add one malformed packet per round")
    parser.add_argument("--gap", type=float, default=0.01, help="seconds between packets")
    args = parser.parse_args()
    assert 1 <= args.count <= 10000
    querier = open_sender("127.0.0.1")
    responder = open_sender("127.0.0.2")
    sent = 0
    for i in range(args.count):
        packets = [(querier, query(i)), (responder, response(i))]
        if args.malformed:
            packets.append((querier, malformed()))
        for sock, p in packets:
            n = sock.sendto(p, (GROUP, PORT))
            assert n == len(p)
            sent += 1
            time.sleep(args.gap)
    querier.close()
    responder.close()
    print(f"sent {sent} packets: queries and malformed from 127.0.0.1, responses from 127.0.0.2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
