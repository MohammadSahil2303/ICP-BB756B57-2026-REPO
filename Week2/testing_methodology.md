# Week 2 – Testing Methodology (Project 1)

1. **Unit tests** (`port_scanner/test_portscan.py`): port-spec parsing (valid, reversed range, out of range), open port + banner detection against a local threaded server, closed port, service identification, public-address ethics gate.
2. **Functional tests** on loopback: `python3 -m http.server` as a known-open port among closed ports; check JSON/CSV/text output.
3. **Cross-validation** against `nmap -sT -p <ports> 127.0.0.1` where Nmap is installed (same open set expected). Not run in the build environment, which had no Nmap; see Week3/validation.md.
4. **Edge cases:** timeouts, 200 threads, hostname resolution, IPv4 only, UDP semantics (`open|filtered`).
5. **Safety:** refuse non-private targets without `--i-have-permission`.
