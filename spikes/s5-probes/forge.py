#!/usr/bin/env python3
"""Forged echo replies for spike S5, run in the upstream namespace.

Usage: forge.py 4|6 IFACE TARGET ROUTER_SRC WRONG_SRC

For the first echo request from ROUTER_SRC to TARGET seen on IFACE it sends, through an
AF_PACKET socket (so the upstream's own nftables rules do not see them): a reply with a wrong
payload token, a reply from WRONG_SRC with the right token, a reply with a corrupted checksum,
and, 1.3 s later (after the attempt deadline), a correct reply. The second request gets a
correct reply after 0.8 s. The kernel's own replies must be dropped by the caller.
"""
import socket
import struct
import sys
import threading
import time

fam, ifname, target, router, wrong = sys.argv[1:6]
v6 = fam == "6"
ethertype = 0x86DD if v6 else 0x0800
af = socket.AF_INET6 if v6 else socket.AF_INET
T, RT, W = (socket.inet_pton(af, a) for a in (target, router, wrong))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def reply(src, ident, seq, data, bad=False):
    typ = 129 if v6 else 0
    icmp = struct.pack("!BBHHH", typ, 0, 0, ident, seq) + data
    if v6:
        pseudo = src + RT + struct.pack("!I3xB", len(icmp), 58)
        c = csum(pseudo + icmp)
    else:
        c = csum(icmp)
    if bad:
        c ^= 0x5555
    icmp = icmp[:2] + struct.pack("!H", c) + icmp[4:]
    if v6:
        return struct.pack("!IHBB", 0x60000000, len(icmp), 58, 64) + src + RT + icmp
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0, src, RT)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + icmp


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))
s.bind((ifname, ethertype))
s.settimeout(1)
seen = 0
end = time.time() + 15
while seen < 2 and time.time() < end:
    try:
        frame, addr = s.recvfrom(65535)
    except socket.timeout:
        continue
    if addr[2] != socket.PACKET_HOST:
        continue
    pkt = frame[14:]
    if v6:
        if len(pkt) < 48 or pkt[6] != 58 or pkt[40] != 128:
            continue
        src, dst, icmp = pkt[8:24], pkt[24:40], pkt[40:]
    else:
        ihl = (pkt[0] & 15) * 4
        if pkt[9] != 1 or pkt[ihl] != 8:
            continue
        src, dst, icmp = pkt[12:16], pkt[16:20], pkt[ihl:]
    if src != RT or dst != T:
        continue
    ident, seq = struct.unpack("!HH", icmp[4:8])
    data = icmp[8:]
    l2 = frame[6:12] + frame[0:6] + frame[12:14]

    def send(p, l2=l2):
        s.send(l2 + p)

    if seen == 0:
        send(reply(T, ident, seq, bytes(x ^ 0xFF for x in data[:16]) + data[16:]))
        send(reply(W, ident, seq, data))
        send(reply(T, ident, seq, data, bad=True))
        threading.Timer(1.3, send, [reply(T, ident, seq, data)]).start()
        print(f"forge: first request seq={seq}: wrong token, wrong source, bad checksum, late reply in 1.3 s", flush=True)
    else:
        threading.Timer(0.8, send, [reply(T, ident, seq, data)]).start()
        print(f"forge: second request seq={seq}: correct reply in 0.8 s", flush=True)
    seen += 1
time.sleep(1.5)
