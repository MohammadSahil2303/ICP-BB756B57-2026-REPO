# Week 3 – Validation of Project 1 (Port Scanner)

All runs on `127.0.0.1` only. Raw output: `validation_run.txt`.

## Test 1 – Ground truth with known listeners
Four local servers were started on random ports (SSH-style, SMTP-style and FTP-style banners, plus one silent server). The scanner swept a 100-port window around them.

| Result | Value |
|---|---|
| Known listeners found | **4 / 4** (recall 100%) |
| Banners identified correctly | SSH, SMTP, FTP identified from banners; silent server reported open with empty banner (correct) |
| Extra open ports | 3 other listeners in the sandbox (38650, 45160, 48746) accepted TCP connections. They are not in my ground-truth set, and I could not list sockets in the sandbox (no `ss`/`netstat`) to identify them, so I treat them as pre-existing local services rather than scanner errors |

## Test 2 – Full sweep performance
Ports 1–65535 on loopback, 0.3 s timeout, 200 threads, no banner grabbing: **2.0 s**, 7 open ports. (Loopback is fast; remote hosts will be limited by RTT and timeouts.)

## Test 3 – Unit tests
5/5 pass (`python3 -m unittest`): parsing, open+banner, closed, service identification, ethics gate.

## Test 4 – Nmap cross-check (not performed here)
Nmap was not installed in the build environment, so I did not compare against it. To repeat on your own machine:
```bash
python3 portscan.py 127.0.0.1 -p 1-1024 -o mine.json
nmap -sT -p 1-1024 127.0.0.1
```
The open-port lists should match.

## Findings / limitations
- Three of the extra listeners return my own `HEAD / HTTP/1.0` probe as the banner, which suggests an echo-type service. The scanner then labels the service `unknown`; banner-pattern detection cannot recognise echo services.
- Service names come from the port number when no banner is available, so a service on a non-standard port may be mislabelled.
- UDP results are inherently ambiguous (`open|filtered`).
- IPv4 only; no OS fingerprinting; SYN mode needs Scapy and root and was not exercised in this environment.
