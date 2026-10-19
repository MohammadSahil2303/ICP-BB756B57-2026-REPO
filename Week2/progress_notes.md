# Week 2 – Progress Notes (Project 1)

**Built:** `port_scanner/portscan.py` – multithreaded TCP connect scanner, UDP probe, optional Scapy SYN scan, service map for 28 common ports, banner grabbing, risk notes (Telnet, FTP, SMB, RDP, VNC, Redis, MongoDB), text/JSON/CSV output, argparse CLI.

**Design decisions**
- Connect scan as default: needs no root and uses only `socket`; SYN scan is optional.
- `ThreadPoolExecutor` (200 workers) because scanning is I/O-bound.
- Ethics gate: public IPs are refused without an explicit flag.

**Issue found and fixed:** the first version only sent an HTTP probe on a fixed list of ports, so an HTTP server on port 8765 was reported as `unknown`. Fix: read passively first (SSH/FTP/SMTP speak first), then fall back to an HTTP `HEAD` probe on any silent port. The same port is now reported as `http`.

**Status:** 5/5 unit tests passing; sample output in `port_scanner/sample_scan.*`.
