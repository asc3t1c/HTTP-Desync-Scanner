# HTTP-Desync-Scanner

![](doc/desync.jpg)

# HTTP Desync Scanner — Usage Guide

A concise, professional usage document for the **HTTP Desync (Request Smuggling) Scanner — upgraded**.
This covers installation, commands, flags, how to run safely (including Burp proxy usage), how to read outputs (JSON + colorized HTML), common errors and troubleshooting, and next steps for verification.

---

## Quick facts
- **Purpose:** actively test for HTTP desynchronization / request‑smuggling (TE/CL, CL/TE, duplicate headers, chunk tricks).  
- **Safety:** **AUTHORIZED TESTING ONLY**. The scanner requires an `--auth-file` that contains the string `AUTH`. Do not use this tool against systems you do not own or for which you do not have explicit written permission.  
- **Output:** JSON (machine readable) and optional colorized HTML (RED / YELLOW / GREEN severity badges).

---

## Installation
1. Save the scanner (e.g. `http_desync_scanner.py`) to your working directory.  
2. Ensure Python 3 installed (3.8+ recommended).  
3. Make the file executable (optional):
```bash
chmod +x http_desync_scanner.py
```

---

## Command line & flags

```
usage: http_desync_scanner.py [--target TARGET] [--port PORT] [--path PATH] [--ssl]
                             [--proxy PROXY] [--concurrency N] [--timeout T]
                             --auth-file FILE [--out FILE] [--html FILE] [--dry-run]
                             [--indicators STR] [--large-threshold N] [--verbose]
```

Important flags:

- `--target` (required) — target hostname or IP (e.g. `example.com`)  
- `--port` — TCP port (default `80`)  
- `--path` — path to use in payload templates (default `/`)  
- `--ssl` — use TLS (HTTPS) — triggers TLS mode to target port  
- `--proxy` — optional HTTP proxy `host:port` (use Burp at `127.0.0.1:8080`)  
  - For HTTPS targets the scanner uses `CONNECT` to the proxy and then TLS over the tunnel  
  - For HTTP with a proxy the request start-line will be rewritten to absolute-form so the proxy forwards it  
- `--concurrency` — number of parallel worker threads (default `4`)  
- `--timeout` — socket timeout (seconds, default `8.0`)  
- `--auth-file` (required) — path to a file that contains the string `AUTH` to confirm authorization  
- `--out` — JSON output file path (default `desync_report.json`)  
- `--html` — optional HTML output file path (colorized report)  
- `--dry-run` — list templates only; do **not** send network traffic  
- `--indicators` — comma-separated custom strings to flag (e.g. `admin,reset,password`)  
- `--large-threshold` — bytes threshold considered “very large” (default `15000`)  
- `--verbose` — enable more logging to stdout

---

## Examples

nu11secur1ty:
```bash
echo AUTH > permission.txt && python http_desync_scanner.py --target your_domain.com --port 80 --auth-file permission.txt --out desync_report.json --html desync_report.html --concurrency 2 --timeout 10
```

Dry-run (show templates only):
```bash
python3 http_desync_scanner.py --target example.com --auth-file permission.txt --dry-run
```

Simple scan against port 80 (one‑liner):
```bash
python3 http_desync_scanner.py --target example.com --port 80 --auth-file permission.txt --out desync_report.json --html desync_report.html
```

Scan via Burp running on `127.0.0.1:8080` (HTTP proxy):
```bash
python3 http_desync_scanner.py --target example.com --port 80 --auth-file permission.txt --proxy 127.0.0.1:8080 --out desync_report.json --html desync_report.html
```

Scan an HTTPS target through proxy (scanner will `CONNECT` first):
```bash
python3 http_desync_scanner.py --target example.com --port 443 --ssl --auth-file permission.txt --proxy 127.0.0.1:8080 --out out.json --html out.html
```

Add custom indicators:
```bash
python3 http_desync_scanner.py --target app.local --auth-file permission.txt --indicators "admin,login,reset" --out report.json
```

Increase concurrency (be careful on production systems):
```bash
python3 http_desync_scanner.py --target example.com --auth-file permission.txt --concurrency 10
```

---

## Output: JSON & HTML

### JSON (`--out`)
The JSON file contains a top-level object:
```json
{
  "target": "example.com",
  "port": 80,
  "path": "/",
  "use_ssl": false,
  "timestamp": 1670000000,
  "results": [
    {
      "template": "te_cl",
      "resp_len": 512,
      "resp_preview": "...",
      "suspected": true,
      "reasons": ["multiple_http_markers_in_response"],
      "severity": "yellow"
    }
  ]
}
```
Key fields:
- `template` — payload name used  
- `resp_len` — bytes received from server  
- `resp_preview` — first part of the response (safe to view)  
- `suspected` — boolean: heuristics flagged something suspicious  
- `reasons` — list of indicators that triggered the suspicion  
- `severity` — `red` / `yellow` / `green` (see below)

### HTML (`--html`)
- A colorized, human‑readable report.  
- Severity legend:
  - **RED** — HIGH severity: likely sensitive/admin strings found (e.g. `/admin`, explicit marker match if used)  
  - **YELLOW** — MEDIUM severity: suspicious signs (multiple HTTP start-lines, unusually large responses)  
  - **GREEN** — LOW severity: no suspicious indicators

Open the HTML file in a browser to review the per-template blocks (response preview, reasons, length). Use this as triage — ALWAYS verify suspected findings manually.

---

## Interpreting results & recommended follow-up
- **RED**: high priority. Manually replay the corresponding request in Burp Repeater (or using saved raw request) to reproduce and investigate. Collect server-side logs or tcpdump if possible.  
- **YELLOW**: medium priority. Re-run the payload, try connection reuse / pipelining / control→test pair (manual) and verify. May be false positives — use Burp to probe further.  
- **GREEN**: likely safe for that payload, but absence of evidence is not proof of absence. Consider more advanced tests if high confidence is required.

Suggested manual verification steps:
1. Replay the suspicious template in Burp Repeater (use `--proxy` to capture full requests).  
2. Test connection reuse: open a single connection and send a benign control request followed immediately by the suspect payload — observe if responses are interleaved or injected.  
3. Ask the application owner to check backend logs (tcpdump / web server logs) for evidence. Server-side logs are the authoritative proof.

---

## Safety & legal
- **Do not** scan systems without explicit written permission. Unauthorized scanning is illegal and unethical.  
- Ensure you have an engagement scope and schedule. Run tests during maintenance windows where applicable.  
- Start with low `--concurrency` and limited `--timeout` to minimize disruption. Increase only with permission and monitoring.

---

## Common errors & troubleshooting

- `ERROR: Authorization file invalid or missing.`  
  - Ensure `--auth-file permission.txt` exists and contains the text `AUTH` (case-insensitive).

- `Proxy CONNECT failed: ...`  
  - The configured proxy rejected the CONNECT request. Verify the proxy host:port and that the proxy allows CONNECT to your destination.

- Socket errors / timeouts:  
  - Increase `--timeout` or reduce `--concurrency`. Network middleboxes (WAFs, IDS) may drop raw-socket traffic — try routing via `--proxy` (Burp) to observe behavior.

- HTML report shows many `YELLOW` flags but nothing obvious:  
  - These are heuristics. Export the raw request into Burp and replay with manual variations (header ordering, casing, chunk sizes) to confirm.

---

## Advanced tips
- Use `--proxy 127.0.0.1:8080` and run Burp to inspect every raw request/response. This allows manual verification and easier reproduction.  
- To verify an individual template manually, copy the raw request from the scanner (or construct one in Burp) and test **connection reuse** scenarios — many desync issues only appear when multiple requests are pipelined on the same TCP connection.  
- Consider capturing a packet trace (`tcpdump -w capture.pcap`) on the testing host when reproducing suspected behavior — network captures + server logs are the strongest evidence.

---

## Example one-line (recommended)
A safe, typical command to run from your terminal (authorized test):
```bash
echo AUTH > permission.txt && python3 http_desync_scanner.py --target example.com --port 80 --auth-file permission.txt --out desync_report.json --html desync_report.html --proxy 127.0.0.1:8080 --concurrency 2 --timeout 10
```

---

If you’d like I can:
- Add **per‑payload unique markers** (very high confidence detection) and update the usage doc to include how markers are shown in the output.  
- Add an option to **save raw `.req` files** for each payload (easy Burp import).  
- Implement an optional **control→test same-connection mode** (pipelined testing) to increase detection reliability.

Which (if any) of those extras do you want me to add now?
