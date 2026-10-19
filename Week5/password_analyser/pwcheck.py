#!/usr/bin/env python3
"""
pwcheck.py - Password Strength Analyzer (Project 2)
ICP-BB756B57-2026 | Cyber Security Self-Learning Internship

Features: regex policy checks, Shannon + charset entropy, pattern detection
(keyboard walks, sequences, repeats, years, leetspeak), common-password check,
crack-time estimates, scoring (0-100), recommendations, passphrase generator,
batch mode and optional HIBP k-anonymity breach check (only 5 hash chars leave
the machine). Passwords are never logged or written to disk.
"""
import argparse, getpass, hashlib, json, math, re, secrets, sys
from collections import Counter

COMMON = set("""password 123456 123456789 12345678 12345 1234567 qwerty abc123 password1 111111
iloveyou admin welcome monkey login letmein dragon passw0rd football baseball master sunshine
princess shadow superman trustno1 hello freedom whatever qazwsx 654321 000000 123123 1q2w3e4r
qwertyuiop zaq12wsx michael jesus ninja mustang password123 admin123 root toor changeme secret
p@ssw0rd p@ssword welcome1 abc12345 test123 default guest iloveyou1 starwars cricket india123""".split())
WALKS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsxedc", "1q2w3e4r5t"]
LEET = str.maketrans("@4310$5!7+8", "aaeiosslttb")
ALPHA = "abcdefghijklmnopqrstuvwxyz"
GUESSES_PER_SEC = {"online (throttled, 100/hr)": 100 / 3600,
                   "offline slow hash (bcrypt, 10^4/s)": 1e4,
                   "offline fast hash (GPU, 10^10/s)": 1e10}
import os
_HERE = os.path.dirname(os.path.abspath(__file__))
try:
    WORDS = open(os.path.join(_HERE, "wordlist.txt")).read().split()   # BIP-39 list, 2048 words
except OSError:
    WORDS = []
EXTRA_WORDS = set("""summer winter spring autumn january february march april june july august september
october november december monday friday sunday correct horse battery staple troubador troubadour trouble
password welcome monkey dragon master shadow sunshine princess football baseball superman iloveyou letmein
admin login secret india delhi mumbai cricket qwerty hello world love angel soccer hockey michael jessica
charlie ashley daniel andrew joshua""".split())
DICT = set(WORDS) | EXTRA_WORDS
WORD_BITS, COMMON_SEP = 12.0, set("-_. !@#$")

def charset_size(pw):
    n = 0
    if re.search(r"[a-z]", pw): n += 26
    if re.search(r"[A-Z]", pw): n += 26
    if re.search(r"\d", pw): n += 10
    if re.search(r"[^A-Za-z0-9]", pw): n += 33
    return n


def entropy_bits(pw):
    """Upper-bound entropy: len * log2(charset)."""
    n = charset_size(pw)
    return len(pw) * math.log2(n) if n else 0.0


def shannon_bits(pw):
    """Empirical Shannon entropy * length (penalises repeated characters)."""
    if not pw: return 0.0
    c = Counter(pw); L = len(pw)
    return -sum(v / L * math.log2(v / L) for v in c.values()) * L


def find_patterns(pw):
    low = pw.lower(); found = []
    norm = low.translate(LEET)
    if low in COMMON: found.append("is a very common password")
    elif norm in COMMON: found.append("is a common password with leetspeak substitutions")
    elif any(c in low for c in COMMON if len(c) >= 6): found.append("contains a common password")
    if re.search(r"(.)\1{2,}", pw): found.append("repeated characters (aaa)")
    if re.fullmatch(r"(.+?)\1+", pw): found.append("a short block repeated")
    for w in WALKS:
        for i in range(len(w) - 3):
            if w[i:i + 4] in low or w[i:i + 4][::-1] in low:
                found.append("keyboard pattern (" + w[i:i + 4] + ")"); break
        else: continue
        break
    for seq in (ALPHA, "0123456789"):
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in low or seq[i:i + 4][::-1] in low:
                found.append("sequential characters (" + seq[i:i + 4] + ")"); break
        else: continue
        break
    if re.search(r"(19|20)\d{2}", pw): found.append("contains a year")
    if re.search(r"\d{4,}$", pw) and len(re.sub(r"\d", "", pw)) < len(pw) / 2:
        found.append("mostly digits")
    return found


def segment_bits(pw):
    """Cheapest way an attacker's model could build this password (DP over segmentations).
    dictionary word ~12 bits (+1 capitalised, +1.5 leetspeak), year 6.5, digit 3.3/char,
    common separators 3, other symbols 5, letters 4.7, repeated char 1."""
    n = len(pw); INF = 1e9
    best = [INF] * (n + 1); best[0] = 0.0
    def single(i):
        c = pw[i]
        if i and pw[i - 1] == c: return 1.0
        if c.isdigit(): return 3.32
        if c.isalpha(): return 4.7
        return 3.0 if c in COMMON_SEP else 5.0
    for i in range(n):
        if best[i] >= INF: continue
        best[i + 1] = min(best[i + 1], best[i] + single(i))
        for j in range(i + 4, min(n, i + 14) + 1):
            sub = pw[i:j]; norm = sub.lower().translate(LEET)
            if norm in DICT and norm.isalpha():
                cost = WORD_BITS + (1 if sub[0].isupper() else 0) + (1.5 if sub.lower() != norm else 0)
                if sub.isupper() and len(sub) > 1: cost += 1
                best[j] = min(best[j], best[i] + cost)
            if sub.lower() in COMMON:
                best[j] = min(best[j], best[i] + 8)
            if j == i + 4 and re.fullmatch(r"(19|20)\d\d", sub):
                best[j] = min(best[j], best[i] + 6.5)
    return best[n]


def effective_bits(pw):
    """Estimated attacker work in bits after modelling dictionary words and patterns."""
    if not pw: return 0.0, []
    pats = find_patterns(pw)
    bits = min(segment_bits(pw), entropy_bits(pw))
    for p in pats:
        if "very common" in p: bits = min(bits, 8)
        elif "common password" in p and "contains" not in p: bits = min(bits, 14)
        elif "keyboard" in p or "sequential" in p: bits *= 0.75
    return max(bits, 0.0), pats


def fmt_time(seconds):
    if seconds < 1: return "instantly"
    for unit, s in (("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400), ("hours", 3600),
                    ("minutes", 60), ("seconds", 1)):
        if seconds >= s:
            v = seconds / s
            return f"{v:,.0f} {unit}" if v < 1e6 else f"{v:.1e} {unit}"
    return "instantly"


def crack_times(bits):
    avg = 2 ** max(bits - 1, 0)
    return {k: fmt_time(avg / v) for k, v in GUESSES_PER_SEC.items()}


def policy_checks(pw):
    return {"length >= 12": len(pw) >= 12, "lowercase": bool(re.search(r"[a-z]", pw)),
            "uppercase": bool(re.search(r"[A-Z]", pw)), "digit": bool(re.search(r"\d", pw)),
            "symbol": bool(re.search(r"[^A-Za-z0-9]", pw)), "no whitespace edges": pw == pw.strip()}


def analyze(pw):
    bits, pats = effective_bits(pw)
    pol = policy_checks(pw)
    score = int(min(100, bits / 80 * 100))
    if len(pw) < 8: score = min(score, 15)
    elif len(pw) < 12: score = min(score, 60)
    if any("common password" in p for p in pats): score = min(score, 10)
    label = ("Very Weak" if score < 20 else "Weak" if score < 40 else "Fair" if score < 60
             else "Strong" if score < 80 else "Very Strong")
    rec = []
    if len(pw) < 12: rec.append("Use at least 12 characters; length matters more than complexity.")
    if not pol["uppercase"] or not pol["lowercase"]: rec.append("Mix upper and lower case letters.")
    if not pol["digit"]: rec.append("Add digits, not only at the end.")
    if not pol["symbol"]: rec.append("Add a symbol, or use a multi-word passphrase instead.")
    for p in pats: rec.append(f"Avoid: password {p}.")
    if not rec: rec.append("Good. Store it in a password manager and enable MFA.")
    elif score < 60: rec.append("Try a random passphrase of 4-5 words (run with --generate).")
    return {"length": len(pw), "entropy_bits": round(bits, 1), "raw_charset_bits": round(entropy_bits(pw), 1),
            "score": score, "rating": label, "policy": pol, "patterns": pats,
            "crack_time": crack_times(bits), "recommendations": rec}


def generate_passphrase(words=5, sep="-"):
    """Diceware-style from a 2048-word list (11 bits/word) + capital + 2 digits (CSPRNG)."""
    if not WORDS: raise RuntimeError("wordlist.txt missing")
    ws = [secrets.choice(WORDS) for _ in range(words)]
    k = secrets.randbelow(words); ws[k] = ws[k].capitalize()
    return sep.join(ws) + sep + f"{secrets.randbelow(100):02d}"


def generator_bits(words=5):
    return round(words * math.log2(2048) + math.log2(words) + math.log2(100), 1)


def hibp_count(pw):
    """k-anonymity: send first 5 SHA-1 hex chars only."""
    import urllib.request
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    req = urllib.request.Request("https://api.pwnedpasswords.com/range/" + h[:5],
                                 headers={"User-Agent": "pwcheck-edu"})
    with urllib.request.urlopen(req, timeout=8) as r:
        for line in r.read().decode().splitlines():
            suf, cnt = line.split(":")
            if suf == h[5:]: return int(cnt)
    return 0


def report(res, mask=None):
    bar = "#" * (res["score"] // 5) + "-" * (20 - res["score"] // 5)
    out = [f"Password: {mask or '(hidden)'}  length={res['length']}",
           f"Strength: [{bar}] {res['score']}/100 - {res['rating']}",
           f"Entropy : {res['entropy_bits']} bits effective ({res['raw_charset_bits']} theoretical)",
           "Policy  : " + ", ".join(f"{'PASS' if v else 'FAIL'} {k}" for k, v in res["policy"].items()),
           "Crack time (average):"]
    out += [f"  - {k}: {v}" for k, v in res["crack_time"].items()]
    out.append("Recommendations:")
    out += [f"  * {r}" for r in res["recommendations"]]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Password strength analyzer")
    ap.add_argument("password", nargs="?", help="omit to be prompted securely")
    ap.add_argument("-f", "--file", help="batch: one password per line")
    ap.add_argument("-g", "--generate", type=int, nargs="?", const=5, help="generate N-word passphrase")
    ap.add_argument("--breach", action="store_true", help="HIBP k-anonymity check (needs internet)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.generate:
        p = generate_passphrase(a.generate); print(p); print(f"True generator entropy: {generator_bits(a.generate)} bits"); print(report(analyze(p))); return
    if a.file:
        rows = []
        for line in open(a.file, encoding="utf-8", errors="ignore"):
            pw = line.rstrip("\n")
            if pw: r = analyze(pw); rows.append((pw[:2] + "*" * (len(pw) - 2), r["score"], r["rating"]))
        print(f"{'MASKED':<20}{'SCORE':<8}RATING")
        for m, s, l in rows: print(f"{m:<20}{s:<8}{l}")
        return
    pw = a.password if a.password is not None else getpass.getpass("Password: ")
    res = analyze(pw)
    if a.breach:
        try: res["breach_count"] = hibp_count(pw)
        except Exception as e: res["breach_count"] = f"unavailable ({e.__class__.__name__})"
    print(json.dumps(res, indent=2) if a.json else report(res, pw[:1] + "*" * (len(pw) - 1)))
    if not a.json and "breach_count" in res: print("Breach check:", res["breach_count"], "known exposures")
    return res


if __name__ == "__main__":
    main()
