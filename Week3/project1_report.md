# Project 1 Report – Network Port Scanner

**Author:** Intern, ICP-BB756B57-2026 · **Tool:** `Week3/port_scanner/portscan.py`

## 1. Problem
Organisations need to know which network services are exposed. Each open port is attack surface; forgotten or insecure services (Telnet, FTP, exposed SMB/RDP, unauthenticated databases) are common initial-access routes.

## 2. Approach
- **TCP connect scan**: `connect_ex()` per port; success means the handshake completed (open).
- **Concurrency**: `ThreadPoolExecutor` with 200 workers because the work is I/O-bound.
- **Service detection**: passive banner read first, HTTP `HEAD` fallback, banner-pattern matching (SSH-, HTTP/, 220 FTP/SMTP, MySQL, POP3, IMAP), then port-number lookup for 28 well-known services.
- **UDP**: send one byte; reply = open, timeout = `open|filtered`, ICMP unreachable (`ConnectionRefusedError`) = closed.
- **SYN scan** (optional): Scapy sends SYN, treats SYN-ACK as open and sends RST.
- **Risk hints**: flags cleartext or commonly exposed services.
- **Ethics gate**: public addresses refused without `--i-have-permission`.

## 3. Results
| Check | Outcome |
|---|---|
| Unit tests | 5/5 pass |
| Known-listener recall | 4/4 found with correct banners for SSH, SMTP, FTP |
| Full loopback sweep (65,535 ports) | 2.0 s |
| Output formats | text, JSON, CSV verified (`sample_scan.*`) |
| Nmap comparison | not run (Nmap unavailable in build environment) |

Sample (loopback test server):
```
PORT      STATE          SERVICE       BANNER / NOTE
8765/tcp  open           http          HTTP/1.0 200 OK
```

## 4. Bug found during testing
HTTP on a non-standard port was reported `unknown` because the HTTP probe was only sent to a fixed port list. Fixed by probing any silent port; regression covered by the sample run.

## 5. Limitations and future work
IPv4 only, no OS fingerprinting, no rate limiting or randomised port order (stealth), UDP ambiguity, SYN mode untested here, echo-type services unidentified. Next: IPv6, CIDR ranges, rate limiting, NSE-style probes, HTML report.

## 6. Defensive takeaways
Close unused ports, firewall management services, replace Telnet/FTP with SSH/SFTP, require authentication on Redis/MongoDB, run scans regularly against your own estate and alert on new open ports.

## 7. Ethics
Tested only on loopback and local test servers. No third-party systems were scanned.
