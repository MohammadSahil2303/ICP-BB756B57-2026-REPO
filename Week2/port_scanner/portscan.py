#!/usr/bin/env python3
"""
portscan.py - Network Port Scanner (Project 1)
ICP-BB756B57-2026 | Cyber Security Self-Learning Internship

Multithreaded TCP connect scanner with banner grabbing, service detection,
UDP probing and JSON/CSV/text output. Pure standard library (Scapy optional
for a SYN scan mode).

ETHICS: scan only systems you own or have written permission to test.
"""
import argparse, concurrent.futures as cf, csv, ipaddress, json, socket, sys, time
from datetime import datetime

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    80: "http", 110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}
TOP_PORTS = sorted(COMMON_SERVICES)
RISKY = {23: "Telnet is unencrypted", 21: "FTP is unencrypted", 445: "SMB exposure (ransomware vector)",
         3389: "RDP exposed to network", 5900: "VNC exposed", 6379: "Redis often unauthenticated",
         27017: "MongoDB often unauthenticated", 139: "NetBIOS exposure"}
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "top":
            ports.update(TOP_PORTS)
        elif "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if not (1 <= a <= b <= 65535):
                raise ValueError(f"bad range {part}")
            ports.update(range(a, b + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"bad port {part}")
            ports.add(p)
    return sorted(ports)


def grab_banner(sock, port, timeout):
    """Passive read first (SSH/FTP/SMTP talk first); fall back to an HTTP probe."""
    try:
        sock.settimeout(min(timeout, 0.5))
        data = sock.recv(256)
    except (socket.timeout, OSError):
        data = b""
    if not data:
        try:
            sock.settimeout(timeout)
            sock.sendall(HTTP_PROBE)
            data = sock.recv(512)
        except (socket.timeout, OSError):
            data = b""
    if not data:
        return ""
    text = data.decode("utf-8", "replace").strip()
    return text.splitlines()[0][:120] if text else ""


def identify(port, banner):
    b = banner.lower()
    if b.startswith("ssh-"): return "ssh"
    if b.startswith("http/") or "server:" in b: return "http"
    if b.startswith("220") and ("ftp" in b): return "ftp"
    if b.startswith("220") and ("smtp" in b or "mail" in b): return "smtp"
    if "mysql" in b: return "mysql"
    if b.startswith("+ok"): return "pop3"
    if b.startswith("* ok"): return "imap"
    return COMMON_SERVICES.get(port, "unknown")


def scan_tcp(host, port, timeout, grab):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            banner = grab_banner(s, port, timeout) if grab else ""
            return {"port": port, "proto": "tcp", "state": "open",
                    "service": identify(port, banner), "banner": banner,
                    "risk": RISKY.get(port, "")}
    except OSError:
        pass
    finally:
        s.close()
    return None


def scan_udp(host, port, timeout):
    """UDP: no reply = open|filtered, reply = open, ICMP unreachable = closed."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.send(b"\x00")
        try:
            s.recv(256)
            state = "open"
        except socket.timeout:
            state = "open|filtered"
        except ConnectionRefusedError:
            return None
        return {"port": port, "proto": "udp", "state": state,
                "service": COMMON_SERVICES.get(port, "unknown"), "banner": "", "risk": ""}
    except OSError:
        return None
    finally:
        s.close()


def syn_scan(host, ports, timeout):  # optional, needs scapy + root
    try:
        from scapy.all import IP, TCP, sr1, send
    except ImportError:
        sys.exit("Scapy not installed: pip install scapy (SYN mode also needs root)")
    out = []
    for p in ports:
        r = sr1(IP(dst=host) / TCP(dport=p, flags="S"), timeout=timeout, verbose=0)
        if r and r.haslayer(TCP) and r[TCP].flags == 0x12:
            send(IP(dst=host) / TCP(dport=p, flags="R"), verbose=0)
            out.append({"port": p, "proto": "tcp", "state": "open",
                        "service": COMMON_SERVICES.get(p, "unknown"), "banner": "", "risk": RISKY.get(p, "")})
    return out


def resolve(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def run(target, ports, udp=False, timeout=1.0, threads=200, grab=True, syn=False):
    host = resolve(target)
    t0 = time.time()
    if syn:
        results = syn_scan(host, ports, timeout)
    else:
        results = []
        fn = (lambda p: scan_udp(host, p, timeout)) if udp else (lambda p: scan_tcp(host, p, timeout, grab))
        with cf.ThreadPoolExecutor(max_workers=threads) as ex:
            for r in ex.map(fn, ports):
                if r:
                    results.append(r)
    results.sort(key=lambda r: r["port"])
    return {"target": target, "ip": host, "scanned": len(ports), "open": results,
            "started": datetime.now().isoformat(timespec="seconds"),
            "duration_s": round(time.time() - t0, 2)}


def render_text(rep):
    lines = [f"Scan report for {rep['target']} ({rep['ip']})",
             f"Ports scanned: {rep['scanned']} | Open: {len(rep['open'])} | {rep['duration_s']}s", "",
             f"{'PORT':<10}{'STATE':<15}{'SERVICE':<14}BANNER / NOTE"]
    for r in rep["open"]:
        note = r["banner"] or ""
        if r["risk"]:
            note += f"  [!] {r['risk']}"
        lines.append(f"{str(r['port'])+'/'+r['proto']:<10}{r['state']:<15}{r['service']:<14}{note}")
    if not rep["open"]:
        lines.append("No open ports found.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Educational port scanner. Authorized targets only.")
    ap.add_argument("target", help="IP or hostname")
    ap.add_argument("-p", "--ports", default="top", help="e.g. 22,80,1-1024 or 'top' (default)")
    ap.add_argument("-u", "--udp", action="store_true", help="UDP scan")
    ap.add_argument("-t", "--timeout", type=float, default=1.0)
    ap.add_argument("-T", "--threads", type=int, default=200)
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--syn", action="store_true", help="SYN scan via Scapy (root)")
    ap.add_argument("-o", "--output", help="write to file; .json or .csv, else text")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="required for non-private targets (ethics gate)")
    a = ap.parse_args(argv)

    ip = resolve(a.target)
    obj = ipaddress.ip_address(ip)
    if not (obj.is_private or obj.is_loopback) and not a.i_have_permission:
        sys.exit("Refusing to scan a public address without --i-have-permission. "
                 "Only scan systems you own or are authorized to test.")
    rep = run(a.target, parse_ports(a.ports), a.udp, a.timeout, a.threads, not a.no_banner, a.syn)
    print(render_text(rep))
    if a.output:
        if a.output.endswith(".json"):
            open(a.output, "w").write(json.dumps(rep, indent=2))
        elif a.output.endswith(".csv"):
            with open(a.output, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["port", "proto", "state", "service", "banner", "risk"])
                w.writeheader(); w.writerows(rep["open"])
        else:
            open(a.output, "w").write(render_text(rep))
    return rep


if __name__ == "__main__":
    main()
