#!/usr/bin/env python3
"""Traffic helper for the spikes.

serve                 TCP and UDP server on port 7 (both families) that
                      answers every connection or datagram with the peer
                      address, then echoes lines (TCP).
conn DST... [opts]    open one TCP connection per (destination, source
                      port) pair and print a JSON summary of the peer
                      addresses seen by the server and of the errors.
udp DST... [opts]     same with one UDP datagram per pair.
send DST... [opts]    one UDP datagram per pair, no reply expected.
long DST [opts]       long-lived TCP flow: one line every --period seconds,
                      runs until SIGTERM/SIGINT, then prints a JSON
                      summary (peer, sent, received, max gap, error).
"""
import argparse
import errno
import json
import os
import select
import signal
import socket
import struct
import sys
import threading
import time
from collections import Counter

PORT = 7


def family_of(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve(args):
    def tcp_loop(sock):
        while True:
            conn, peer = sock.accept()
            threading.Thread(target=tcp_client, args=(conn, peer), daemon=True).start()

    def tcp_client(conn, peer):
        try:
            conn.sendall((peer[0].removeprefix("::ffff:") + "\n").encode())
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    # Reply from the address the datagram was sent to (AnyIP ranges), using
    # IP_PKTINFO / IPV6_PKTINFO, so that replies match the client's flow.
    IP_PKTINFO, IPV6_RECVPKTINFO, IPV6_PKTINFO = 8, 49, 50

    def udp_loop(sock, v6):
        level = socket.IPPROTO_IPV6 if v6 else socket.IPPROTO_IP
        sock.setsockopt(level, IPV6_RECVPKTINFO if v6 else IP_PKTINFO, 1)
        while True:
            _data, anc, _flags, peer = sock.recvmsg(4096, 256)
            reply = [(lvl, typ, val) for lvl, typ, val in anc if typ == (IPV6_PKTINFO if v6 else IP_PKTINFO)]
            if reply and not v6:
                # in_pktinfo: ifindex, spec_dst, addr -> answer from addr, any interface
                reply = [(level, IP_PKTINFO, struct.pack("i4s4s", 0, reply[0][2][8:12], b"\0" * 4))]
            elif reply:
                reply = [(level, IPV6_PKTINFO, reply[0][2][:16] + struct.pack("i", 0))]
            sock.sendmsg([(peer[0] + "\n").encode()], reply, 0, peer)

    t = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    t.bind(("::", args.port))
    t.listen(1024)
    u4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u4.bind(("0.0.0.0", args.port))
    u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    u6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    u6.bind(("::", args.port))
    threading.Thread(target=udp_loop, args=(u4, False), daemon=True).start()
    threading.Thread(target=udp_loop, args=(u6, True), daemon=True).start()
    tcp_loop(t)


def err_name(e):
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, OSError) and e.errno:
        return errno.errorcode.get(e.errno, str(e.errno))
    return type(e).__name__


def make_socket(dst, kind, args, sport):
    s = socket.socket(family_of(dst), kind)
    s.settimeout(args.timeout)
    if args.mark:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(args.mark, 0))
    if args.device:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.device.encode())
    if args.unicast_if:
        idx = socket.if_nametoindex(args.unicast_if)
        if ":" in dst:
            s.setsockopt(socket.IPPROTO_IPV6, 76, struct.pack("!I", idx))  # IPV6_UNICAST_IF, also network order
        else:
            s.setsockopt(socket.IPPROTO_IP, 50, struct.pack("!I", idx))  # IP_UNICAST_IF
    if args.src or sport:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.src or ("::" if ":" in dst else "0.0.0.0"), sport))
    return s


def pairs(args):
    for i in range(args.count):
        dst = args.dst[i % len(args.dst)]
        sport = args.sport + i if args.sport else 0
        yield dst, sport


def conn(args):
    peers, errors = Counter(), Counter()
    for dst, sport in pairs(args):
        s = make_socket(dst, socket.SOCK_STREAM, args, sport)
        try:
            s.connect((dst, args.port))
            line = s.makefile().readline().strip()
            peers[line or "empty"] += 1
            if args.local:
                peers["local=" + s.getsockname()[0]] += 1
        except Exception as e:  # noqa: BLE001 - spike tool, report everything
            errors[err_name(e)] += 1
        finally:
            s.close()
    print(json.dumps({"peers": peers, "errors": errors}, sort_keys=True))


def udp(args):
    peers, errors = Counter(), Counter()
    for dst, sport in pairs(args):
        s = make_socket(dst, socket.SOCK_DGRAM, args, sport)
        try:
            s.sendto(b"x", (dst, args.port))
            data, _ = s.recvfrom(4096)
            peers[data.decode().strip()] += 1
        except Exception as e:  # noqa: BLE001
            errors[err_name(e)] += 1
        finally:
            s.close()
    print(json.dumps({"peers": peers, "errors": errors}, sort_keys=True))


def send(args):
    """One UDP datagram per (destination, source port) pair, no reply expected."""
    errors = Counter()
    sent = 0
    for dst, sport in pairs(args):
        s = make_socket(dst, socket.SOCK_DGRAM, args, sport)
        try:
            s.sendto(b"x", (dst, args.port))
            sent += 1
        except Exception as e:  # noqa: BLE001
            errors[err_name(e)] += 1
        finally:
            s.close()
    print(json.dumps({"sent": sent, "errors": errors}, sort_keys=True))


def long(args):
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    result = {"peer": None, "sent": 0, "received": 0, "max_gap": 0.0, "error": None}
    s = make_socket(args.dst[0], socket.SOCK_STREAM, args, args.sport)
    try:
        s.connect((args.dst[0], args.port))
        f = s.makefile("rb")
        result["peer"] = f.readline().decode().strip()
        if args.ready:
            open(args.ready, "w").close()
        last = time.monotonic()
        s.settimeout(None)
        s.setblocking(False)
        pending = b""
        while not stop.is_set():
            s.sendall(b"ping\n")
            result["sent"] += 1
            deadline = time.monotonic() + args.period
            while time.monotonic() < deadline and not stop.is_set():
                r, _, _ = select.select([s], [], [], max(0.0, deadline - time.monotonic()))
                if r:
                    data = s.recv(4096)
                    if not data:
                        raise ConnectionResetError(errno.ECONNRESET, "closed by peer")
                    pending += data
                    n = pending.count(b"\n")
                    if n:
                        result["received"] += n
                        pending = pending.rsplit(b"\n", 1)[1]
                        now = time.monotonic()
                        result["max_gap"] = max(result["max_gap"], round(now - last, 3))
                        last = now
            if time.monotonic() - last > args.fail_after:
                raise TimeoutError(errno.ETIMEDOUT, "no echo")
    except Exception as e:  # noqa: BLE001
        result["error"] = err_name(e)
    finally:
        s.close()
    print(json.dumps(result, sort_keys=True))
    sys.stdout.flush()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["serve", "conn", "udp", "send", "long"])
    p.add_argument("dst", nargs="*")
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--sport", type=int, default=0, help="first source port (0 = ephemeral)")
    p.add_argument("--src", default=None)
    p.add_argument("--mark", default=None)
    p.add_argument("--device", default=None)
    p.add_argument("--unicast-if", default=None, help="IP_UNICAST_IF / IPV6_UNICAST_IF interface")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--period", type=float, default=0.2)
    p.add_argument("--fail-after", type=float, default=3.0)
    p.add_argument("--ready", default=None, help="file created once connected")
    p.add_argument("--local", action="store_true", help="also count local addresses")
    args = p.parse_args()
    {"serve": serve, "conn": conn, "udp": udp, "send": send, "long": long}[args.mode](args)


if __name__ == "__main__":
    main()
