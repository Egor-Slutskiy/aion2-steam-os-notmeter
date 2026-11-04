#!/usr/bin/env python3
"""NotMeter Linux capture helper.

Captures IPv4 TCP packets with a Linux packet socket and streams them to the
NotMeter Proton plugin (NotMeter.Capture.Proton.dll) over 127.0.0.1.

Replaces Npcap: Wine/Proton cannot load the Npcap kernel driver, so the
capture runs natively here and the meter (inside Proton) just reads the stream.

Needs root (or CAP_NET_RAW). Uses only the Python standard library.

Wire protocol (all integers big-endian):
  client -> helper : one line "NOTMETER1 port=<n>\n"   (port=0 means every TCP port)
  helper -> client : one line "OK <helper version>\n"  or  "ERR <message>\n"
  helper -> client : records, repeated:
      u8  direction   (0 = inbound to this machine, 1 = outbound)
      u32 seconds     (unix time)
      u32 microseconds
      u16 length
      [length] raw IPv4 packet, starting at the IP header
"""

import argparse
import ctypes
import os
import select
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict

VERSION = "1.0.0"
DEFAULT_PORT = 47380

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
PACKET_OUTGOING = 4
SO_ATTACH_FILTER = 26
SOL_SOCKET = 1

# Packet types we pass on: to us (HOST) and from us (OUTGOING).
PACKET_HOST = 0
WANTED_PKTTYPES = (PACKET_HOST, PACKET_OUTGOING)


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ---------------------------------------------------------------- BPF filter

class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter))]


def build_bpf(port):
    """Classic BPF for a SOCK_DGRAM packet socket (offsets start at the IP header).

    Accepts unfragmented IPv4 TCP; when port != 0 only that src/dst port.
    """
    LD_W_ABS, LDB_ABS, LDH_ABS, LDH_IND = 0x20, 0x30, 0x28, 0x48
    LDXB_MSH = 0xB1
    JEQ, JSET = 0x15, 0x45
    RET = 0x06
    SKF_AD_PROTOCOL = (-0x1000) & 0xFFFFFFFF  # SKF_AD_OFF + 0: skb->protocol

    # (opcode, true-label, false-label, k); labels are resolved below.
    prog = [
        (LD_W_ABS, None, None, SKF_AD_PROTOCOL),
        (JEQ, None, "drop", ETH_P_IP),
        (LDB_ABS, None, None, 9),             # ip protocol
        (JEQ, None, "drop", 6),               # tcp
        (LDH_ABS, None, None, 6),             # flags + fragment offset
        (JSET, "drop", None, 0x1FFF),         # no fragments
    ]
    if port:
        prog += [
            (LDXB_MSH, None, None, 0),        # x = ip header length
            (LDH_IND, None, None, 0),         # tcp source port
            (JEQ, "accept", None, port),
            (LDH_IND, None, None, 2),         # tcp destination port
            (JEQ, "accept", "drop", port),
        ]
    labels = {"accept": len(prog), "drop": len(prog) + 1}
    prog += [(RET, None, None, 0x40000), (RET, None, None, 0)]

    def rel(i, label):
        return 0 if label is None else labels[label] - i - 1

    arr = (SockFilter * len(prog))(*[
        SockFilter(op, rel(i, jt), rel(i, jf), k & 0xFFFFFFFF)
        for i, (op, jt, jf, k) in enumerate(prog)])
    return arr, SockFprog(len(prog), arr)


def open_capture(port):
    # ETH_P_ALL: sockets bound to a single protocol never see outgoing packets.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    arr, fprog = build_bpf(port)
    s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))
    del arr  # the kernel has its own copy now
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
    return s


# ------------------------------------------------------------ peer checking

def peer_uid(conn):
    """uid that owns the client end of a loopback TCP connection.

    Looks in /proc/net/tcp and /proc/net/tcp6: .NET and many other runtimes use
    dual-stack IPv6 sockets, so a connect to 127.0.0.1 shows up in tcp6 as
    ::ffff:127.0.0.1.
    """
    try:
        peer_port = conn.getpeername()[1]
        my_port = conn.getsockname()[1]
    except OSError:
        return None

    def loopback_port(field):
        addr, _, port = field.rpartition(":")
        # 127.0.0.1 is "0100007F" in tcp and ends the mapped address in tcp6.
        return int(port, 16) if addr.endswith("0100007F") else None

    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if (len(parts) > 7 and loopback_port(parts[1]) == peer_port
                            and loopback_port(parts[2]) == my_port):
                        return int(parts[7])
        except (OSError, ValueError):
            continue
    return None


# ------------------------------------------------------------------ session

class Dedup:
    """Drops the same packet seen twice in a short window (bridges, veth...)."""

    def __init__(self, size=4096):
        self.size = size
        self.seen = OrderedDict()

    def first_time(self, key):
        if key in self.seen:
            return False
        self.seen[key] = None
        if len(self.seen) > self.size:
            self.seen.popitem(last=False)
        return True


def serve_client(conn, args):
    name = "%s:%d" % conn.getpeername()
    cap = None
    try:
        conn.settimeout(10)
        hello = b""
        while not hello.endswith(b"\n") and len(hello) < 256:
            chunk = conn.recv(256)
            if not chunk:
                return
            hello += chunk
        words = hello.decode("ascii", "replace").split()
        if not words or words[0] != "NOTMETER1":
            conn.sendall(b"ERR bad hello\n")
            return
        opts = dict(w.split("=", 1) for w in words[1:] if "=" in w)
        port = args.game_port if args.game_port is not None else int(opts.get("port", "0") or 0)
        if not 0 <= port <= 65535:
            port = 0

        try:
            cap = open_capture(port)
        except PermissionError:
            conn.sendall(b"ERR helper needs root (CAP_NET_RAW)\n")
            return
        conn.sendall(("OK %s\n" % VERSION).encode())
        conn.settimeout(None)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log("%s connected, filter: %s" % (name, "tcp port %d" % port if port else "tcp"))

        dedup = Dedup()
        excluded = set(args.exclude)
        only = set(args.iface) if args.iface else None
        sent = 0
        while True:
            r, _, _ = select.select([cap, conn], [], [], 5)
            if conn in r:
                # Client never sends after the hello; readable means closed.
                if not conn.recv(1):
                    break
            if cap not in r:
                continue
            out = []
            for _ in range(256):
                try:
                    data, addr = cap.recvfrom(65535, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    break
                ifname, proto, pkttype = addr[0], addr[1], addr[2]
                if proto != ETH_P_IP or pkttype not in WANTED_PKTTYPES:
                    continue
                if ifname in excluded or (only is not None and ifname not in only):
                    continue
                if len(data) < 40:
                    continue
                # Trust the IP total length: Ethernet pads short frames.
                total = (data[2] << 8) | data[3]
                if total < 40 or total > len(data):
                    continue
                data = data[:total]
                ihl = (data[0] & 0x0F) * 4
                if ihl < 20 or total < ihl + 20:
                    continue
                # Skip packets without TCP payload (pure ACKs etc.).
                if total <= ihl + (data[ihl + 12] >> 4) * 4:
                    continue
                key = (pkttype, data[12:20], data[ihl:ihl + 8], len(data))
                if not dedup.first_time(key):
                    continue
                now = time.time()
                sec = int(now)
                usec = int((now - sec) * 1_000_000)
                direction = 1 if pkttype == PACKET_OUTGOING else 0
                out.append(struct.pack(">BIIH", direction, sec, usec, len(data)) + data)
            if out:
                conn.sendall(b"".join(out))
                sent += len(out)
        log("%s disconnected after %d packets" % (name, sent))
    except (BrokenPipeError, ConnectionResetError):
        log("%s disconnected" % name)
    except Exception as e:  # keep the server alive whatever happens
        log("%s error: %r" % (name, e))
    finally:
        if cap is not None:
            cap.close()
        conn.close()


# --------------------------------------------------------------- diagnostics

ETH_P_IPV6 = 0x86DD


def _proc_addr(field, v6):
    """'0100007F:1F90' -> ('127.0.0.1', 8080) for /proc/net/tcp[6] fields."""
    addr, port = field.split(":")
    raw = bytes.fromhex(addr)
    # The kernel prints each 32-bit word in host (little-endian) order.
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    if v6:
        if raw[:12] == b"\0" * 10 + b"\xff\xff":
            return socket.inet_ntop(socket.AF_INET, raw[12:]), int(port, 16)
        return socket.inet_ntop(socket.AF_INET6, raw), int(port, 16)
    return socket.inet_ntop(socket.AF_INET, raw), int(port, 16)


def game_connections():
    """TCP connections owned by processes whose command line mentions aion2.exe."""
    pids = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % d, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").lower()
        except OSError:
            continue
        if b"aion2.exe" in cmd and b"notmeter.exe" not in cmd and b"notmeter-capture" not in cmd:
            pids.append(int(d))
    inodes = {}
    for pid in pids:
        try:
            for fd in os.listdir("/proc/%d/fd" % pid):
                try:
                    link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
                except OSError:
                    continue
                if link.startswith("socket:["):
                    inodes[link[8:-1]] = pid
        except OSError:
            continue
    states = {"01": "ESTABLISHED", "02": "SYN_SENT", "06": "TIME_WAIT", "08": "CLOSE_WAIT", "0A": "LISTEN"}
    conns = []
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) > 9 and parts[9] in inodes:
                        local = _proc_addr(parts[1], v6)
                        remote = _proc_addr(parts[2], v6)
                        conns.append(("tcp6" if v6 else "tcp", local, remote,
                                      states.get(parts[3], parts[3]), inodes[parts[9]]))
        except OSError:
            pass
    return pids, conns


def run_diag(seconds):
    print("== NotMeter capture diagnostics (%s)" % VERSION)
    print("\n== interfaces")
    try:
        import subprocess
        print(subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True).stdout.rstrip())
        print("\n== routes")
        print(subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True).stdout.rstrip())
        print(subprocess.run(["ip", "-6", "route", "get", "2606:4700::1111"], capture_output=True, text=True).stdout.rstrip()
              or "(no IPv6 route)")
    except Exception as e:
        print("ip not available:", e)

    pids, conns = game_connections()
    print("\n== Aion2 processes: %s" % (pids or "NOT FOUND (start the game first)"))
    for fam, local, remote, state, pid in conns:
        if state != "LISTEN":
            print("  %-4s %s:%d -> %s:%d %s (pid %d)" % (fam, local[0], local[1], remote[0], remote[1], state, pid))
    game_ports = {local[1] for _, local, _, st, _ in conns if st != "LISTEN"}

    print("\n== capturing all TCP for %d s, play/move in the game..." % seconds)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    s.settimeout(0.5)
    flows = {}
    end = time.time() + seconds
    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        ifname, proto, pkttype = addr[0], addr[1], addr[2]
        if ifname == "lo" or pkttype not in WANTED_PKTTYPES:
            continue
        if proto == ETH_P_IP and len(data) >= 40 and data[9] == 6:
            ihl = (data[0] & 0x0F) * 4
            src, dst = socket.inet_ntop(socket.AF_INET, data[12:16]), socket.inet_ntop(socket.AF_INET, data[16:20])
            fam = "ipv4"
        elif proto == ETH_P_IPV6 and len(data) >= 60 and data[6] == 6:
            ihl = 40
            src, dst = socket.inet_ntop(socket.AF_INET6, data[8:24]), socket.inet_ntop(socket.AF_INET6, data[24:40])
            fam = "ipv6"
        else:
            continue
        sport, dport = struct.unpack(">HH", data[ihl:ihl + 4])
        direction = "out" if pkttype == PACKET_OUTGOING else "in "
        key = (ifname, fam, direction, src, sport, dst, dport)
        n, b = flows.get(key, (0, 0))
        flows[key] = (n + 1, b + len(data))
    s.close()
    top = sorted(flows.items(), key=lambda kv: -kv[1][1])[:25]
    for (ifname, fam, direction, src, sport, dst, dport), (n, b) in top:
        mark = "  <== game socket" if sport in game_ports or dport in game_ports else ""
        print("  %-12s %s %s %s:%d -> %s:%d  %d pkts %d bytes%s" % (
            ifname, fam, direction, src, sport, dst, dport, n, b, mark))
    if not top:
        print("  no TCP packets seen")
    print("\nCopy everything above and send it.")


def main():
    p = argparse.ArgumentParser(description="NotMeter capture helper for Linux / Steam Deck")
    p.add_argument("--listen", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port for the plugin (default %d)" % DEFAULT_PORT)
    p.add_argument("--game-port", type=int, default=None,
                   help="override the game server port the meter asks for (0 = all TCP)")
    p.add_argument("--iface", action="append", default=[],
                   help="capture only on this interface (repeatable, default: all)")
    p.add_argument("--exclude", action="append", default=["lo"],
                   help="interfaces to ignore (default: lo)")
    p.add_argument("--allow-uid", type=int, action="append", default=[],
                   help="only serve clients running as this uid (default: SUDO_UID / PKEXEC_UID, else any)")
    p.add_argument("--any-uid", action="store_true", help="serve clients of any local user")
    p.add_argument("--diag", type=int, nargs="?", const=20, metavar="SECONDS",
                   help="print game connections and captured TCP flows, then exit")
    args = p.parse_args()

    if args.diag:
        run_diag(args.diag)
        return

    if os.geteuid() != 0:
        log("warning: not running as root, capture will probably fail (run with sudo)")

    allowed = set(args.allow_uid)
    if not allowed and not args.any_uid:
        for var in ("SUDO_UID", "PKEXEC_UID"):
            if os.environ.get(var, "").isdigit():
                allowed.add(int(os.environ[var]))
    if args.any_uid:
        allowed = set()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.listen, args.port))
    srv.listen(8)
    log("NotMeter capture helper %s listening on %s:%d%s" % (
        VERSION, args.listen, args.port,
        "" if not allowed else " (uids %s)" % ",".join(map(str, sorted(allowed)))))

    while True:
        conn, _ = srv.accept()
        if allowed:
            uid = peer_uid(conn)
            if uid not in allowed:
                log("refused client with uid %s" % uid)
                try:
                    conn.sendall(b"ERR not allowed\n")
                finally:
                    conn.close()
                continue
        threading.Thread(target=serve_client, args=(conn, args), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
