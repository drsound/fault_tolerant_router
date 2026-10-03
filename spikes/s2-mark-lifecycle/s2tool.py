#!/usr/bin/env python3
"""Extra traffic modes for spike S2 (peer.py provides the server).

syn DST [opts]       --count unanswered TCP connects held for --duration
                     seconds (the kernel retransmits the SYNs).
stream DST [opts]    --count one-way UDP flows from consecutive source
                     ports, one datagram per flow every --period seconds
                     for --duration seconds.
bulk DST [opts]      TCP transfer of --bytes to the echo server of
                     peer.py and back; prints ok/error and the duration.
ping DST [opts]      ICMP / ICMPv6 echo on a raw socket with optional
                     SO_MARK, SO_BINDTODEVICE and bound source; prints
                     replies and losses.
ttl DST [opts]       --count UDP datagrams with TTL / hop limit --ttl.
dgram DST [opts]     --count UDP datagrams to a unicast, broadcast or
                     multicast DST with SO_BROADCAST; --device binds the
                     socket (SO_BINDTODEVICE) and selects the multicast
                     interface; --ttl sets the multicast TTL / hop limit.
mroute GROUP [opts]  multicast routing entry (MRT_INIT / MRT6_INIT): source
                     --src, input interface --iif, output interface --oif;
                     holds the routing socket until SIGTERM.
"""
import argparse
import errno
import json
import os
import select
import signal
import socket
import struct
import time


def fam(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def err_name(e):
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, OSError) and e.errno:
        return errno.errorcode.get(e.errno, str(e.errno))
    return type(e).__name__


def opts(s, a, sport=0, dst="0.0.0.0"):
    if a.mark:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(a.mark, 0))
    if a.device:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, a.device.encode())
    if a.src or sport:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.src or ("::" if ":" in dst else "0.0.0.0"), sport))


def syn(a):
    socks = []
    for i in range(a.count):
        s = socket.socket(fam(a.dst), socket.SOCK_STREAM)
        opts(s, a, a.sport + i if a.sport else 0, a.dst)
        s.setblocking(False)
        try:
            s.connect((a.dst, a.port))
        except BlockingIOError:
            pass
        socks.append(s)
    time.sleep(a.duration)
    states = {}
    for s in socks:
        e = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        k = errno.errorcode.get(e, "pending") if e else "pending"
        states[k] = states.get(k, 0) + 1
        s.close()
    print(json.dumps(states, sort_keys=True))


def stream(a):
    socks = []
    for i in range(a.count):
        s = socket.socket(fam(a.dst), socket.SOCK_DGRAM)
        opts(s, a, a.sport + i, a.dst)
        socks.append(s)
    sent, errors = 0, {}
    end = time.monotonic() + a.duration
    while time.monotonic() < end:
        for s in socks:
            try:
                s.sendto(b"x", (a.dst, a.port))
                sent += 1
            except OSError as e:
                errors[err_name(e)] = errors.get(err_name(e), 0) + 1
        time.sleep(a.period)
    print(json.dumps({"sent": sent, "errors": errors}, sort_keys=True))


def bulk(a):
    t0 = time.monotonic()
    res = {"ok": False, "error": None}
    s = socket.socket(fam(a.dst), socket.SOCK_STREAM)
    s.settimeout(a.timeout)
    try:
        opts(s, a, 0, a.dst)
        s.connect((a.dst, a.port))
        f = s.makefile("rb")
        f.readline()
        payload = os.urandom(a.bytes // 2).hex().encode()[: a.bytes] + b"\n"
        s.sendall(payload)
        got = f.read(len(payload))
        res["ok"] = got == payload
        if not res["ok"]:
            res["error"] = "short read %d" % len(got)
    except Exception as e:  # noqa: BLE001
        res["error"] = err_name(e)
    finally:
        s.close()
    res["seconds"] = round(time.monotonic() - t0, 2)
    print(json.dumps(res, sort_keys=True))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    t = (t >> 16) + (t & 0xFFFF)
    t += t >> 16
    return ~t & 0xFFFF


def ping(a):
    v6 = ":" in a.dst
    s = socket.socket(fam(a.dst), socket.SOCK_RAW, socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
    opts(s, a, 0, a.dst)
    ident = os.getpid() & 0xFFFF
    replies = lost = 0
    for seq in range(1, a.count + 1):
        token = os.urandom(16)
        typ = 128 if v6 else 8
        hdr = struct.pack("!BBHHH", typ, 0, 0, ident, seq)
        pkt = hdr + token
        if not v6:
            pkt = struct.pack("!BBHHH", typ, 0, csum(pkt), ident, seq) + token
        try:
            s.sendto(pkt, (a.dst, 0))
        except OSError as e:
            print(json.dumps({"error": err_name(e)}))
            return
        deadline = time.monotonic() + a.timeout
        ok = False
        while not ok and time.monotonic() < deadline:
            r, _, _ = select.select([s], [], [], max(0, deadline - time.monotonic()))
            if not r:
                break
            data, peer = s.recvfrom(2048)
            if not v6:
                data = data[(data[0] & 0x0F) * 4:]
            if len(data) < 24:
                continue
            t, _c, _k, i, q = struct.unpack("!BBHHH", data[:8])
            if t == (129 if v6 else 0) and i == ident and q == seq and data[8:24] == token and peer[0] == a.dst:
                ok = True
        replies += ok
        lost += not ok
    print(json.dumps({"replies": replies, "lost": lost}, sort_keys=True))


def ttl(a):
    s = socket.socket(fam(a.dst), socket.SOCK_DGRAM)
    if ":" in a.dst:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, a.ttl)
    else:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, a.ttl)
    for _ in range(a.count):
        s.sendto(b"x", (a.dst, a.port))
        time.sleep(0.05)
    print(json.dumps({"sent": a.count}))


def dgram(a):
    v6 = ":" in a.dst
    s = socket.socket(fam(a.dst), socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if a.device:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, a.device.encode())
        idx = socket.if_nametoindex(a.device)
        if v6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
        else:  # struct ip_mreqn: multiaddr, address, ifindex
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("4s4si", b"\0" * 4, b"\0" * 4, idx))
    if v6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, a.ttl)
    else:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, a.ttl)
    if a.src or a.sport:
        s.bind((a.src or ("::" if v6 else "0.0.0.0"), a.sport))
    sent, errors = 0, {}
    for _ in range(a.count):
        try:
            s.sendto(b"x", (a.dst, a.port))
            sent += 1
        except OSError as e:
            errors[err_name(e)] = errors.get(err_name(e), 0) + 1
        time.sleep(0.05)
    print(json.dumps({"sent": sent, "errors": errors}, sort_keys=True))


def mroute(a):
    """One (source, group) forwarding entry from --iif to --oif (vif/mif 0 and 1)."""
    v6 = ":" in a.dst
    iif, oif = socket.if_nametoindex(a.iif), socket.if_nametoindex(a.oif)
    if v6:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.setsockopt(socket.IPPROTO_IPV6, 200, struct.pack("i", 1))  # MRT6_INIT
        for mifi, idx in ((0, iif), (1, oif)):  # MRT6_ADD_MIF, struct mif6ctl
            s.setsockopt(socket.IPPROTO_IPV6, 202, struct.pack("@HBBHI", mifi, 0, 1, idx, 0))
        sin6 = lambda addr: struct.pack("=HHI16sI", socket.AF_INET6, 0, 0, socket.inet_pton(socket.AF_INET6, addr), 0)
        ifset = struct.pack("=8I", 1 << 1, *[0] * 7)  # output: mif 1
        s.setsockopt(socket.IPPROTO_IPV6, 204, sin6(a.src) + sin6(a.dst) + struct.pack("=H2x", 0) + ifset)  # MRT6_ADD_MFC
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
        s.setsockopt(socket.IPPROTO_IP, 200, struct.pack("i", 1))  # MRT_INIT
        for vifi, idx in ((0, iif), (1, oif)):  # MRT_ADD_VIF, struct vifctl with VIFF_USE_IFINDEX
            s.setsockopt(socket.IPPROTO_IP, 202, struct.pack("@HBBIi4s", vifi, 0x8, 1, 0, idx, b"\0" * 4))
        ttls = bytes([0, 1] + [0] * 30)  # forward on vif 1 when TTL > 1
        s.setsockopt(socket.IPPROTO_IP, 204, struct.pack("@4s4sH32sIIIi", socket.inet_aton(a.src),
                                                         socket.inet_aton(a.dst), 0, ttls, 0, 0, 0, 0))  # MRT_ADD_MFC
    print(json.dumps({"mroute": "ok"}), flush=True)
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        time.sleep(1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["syn", "stream", "bulk", "ping", "ttl", "dgram", "mroute"])
    p.add_argument("dst")
    p.add_argument("--port", type=int, default=7)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--sport", type=int, default=0)
    p.add_argument("--src", default=None)
    p.add_argument("--mark", default=None)
    p.add_argument("--device", default=None)
    p.add_argument("--duration", type=float, default=5.0)
    p.add_argument("--period", type=float, default=0.2)
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--bytes", type=int, default=200000)
    p.add_argument("--ttl", type=int, default=1)
    p.add_argument("--iif", default=None)
    p.add_argument("--oif", default=None)
    a = p.parse_args()
    {"syn": syn, "stream": stream, "bulk": bulk, "ping": ping, "ttl": ttl, "dgram": dgram, "mroute": mroute}[a.mode](a)


if __name__ == "__main__":
    main()
