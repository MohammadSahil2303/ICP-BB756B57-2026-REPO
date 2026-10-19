# Week 1 – Lab Environment Setup

| Item | Choice |
|---|---|
| Host | Linux (Ubuntu 24), Python 3.12 |
| Isolation | Loopback (`127.0.0.1`) targets and local test servers only; no third-party hosts |
| Language / libs | Python standard library (`socket`, `concurrent.futures`, `re`, `math`, `secrets`); `unittest`; Scapy optional |
| Reference tools | Nmap, tcpdump/Wireshark and Git are recommended on the learner machine; they were not available in the build sandbox |
| Test targets | `python3 -m http.server` on port 8765; a threaded banner server inside the unit tests |
| Later-project lab (not built) | Kali Linux + Metasploitable2/DVWA on a host-only VirtualBox network |

## Setup steps
```bash
sudo apt update && sudo apt install -y python3 python3-pip git nmap tcpdump
pip install scapy                      # optional, SYN mode (needs root)
python3 -m http.server 8765 --bind 127.0.0.1 &   # safe local target
```

## Safety rules
1. Targets are loopback or VMs on an isolated host-only network.
2. Public IPs need written permission; the scanner enforces `--i-have-permission`.
3. No real credentials are used in tests and no passwords are logged.
