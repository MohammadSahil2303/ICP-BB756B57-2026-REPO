# portscan.py – Network Port Scanner

Educational scanner: TCP connect (default), UDP probe, optional Scapy SYN scan (`--syn`, root), banner grabbing, service detection, risk hints, text/JSON/CSV output.

```bash
python3 portscan.py 127.0.0.1                      # 28 common ports ("top")
python3 portscan.py 192.168.1.10 -p 1-1024 -o out.json
python3 portscan.py 127.0.0.1 -u -p 53,123,161     # UDP
python3 portscan.py scanme.example --i-have-permission -p 22,80,443   # public host: authorised only
```
| Flag | Meaning |
|---|---|
| `-p` | ports: `22,80`, `1-1024`, `top` |
| `-u` | UDP scan |
| `-t / -T` | timeout seconds / thread count |
| `--no-banner` | skip banner grabbing |
| `--syn` | SYN scan via Scapy (root) |
| `-o` | `.json`, `.csv` or text file |
| `--i-have-permission` | required for non-private targets |

Tests: `python3 -m unittest`. Standard library only.
**Use only on systems you own or are authorised to test.**
