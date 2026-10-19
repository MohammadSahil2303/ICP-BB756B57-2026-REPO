#!/usr/bin/env python3
"""pwcheck_v1.py - Week 4 working version: regex policy + entropy + common list.
Week 5 adds pattern detection, crack-time estimates, breach check, generator."""
import math, re, getpass, sys
COMMON = {"password", "123456", "qwerty", "admin", "letmein", "welcome", "abc123", "iloveyou"}

def entropy(pw):
    size = sum(n for pat, n in ((r"[a-z]", 26), (r"[A-Z]", 26), (r"\d", 10), (r"[^A-Za-z0-9]", 33)) if re.search(pat, pw))
    return len(pw) * math.log2(size) if size else 0

def analyze(pw):
    issues = []
    if len(pw) < 12: issues.append("shorter than 12 characters")
    if not re.search(r"[a-z]", pw): issues.append("no lowercase")
    if not re.search(r"[A-Z]", pw): issues.append("no uppercase")
    if not re.search(r"\d", pw): issues.append("no digit")
    if not re.search(r"[^A-Za-z0-9]", pw): issues.append("no symbol")
    if pw.lower() in COMMON: issues.append("common password")
    bits = entropy(pw)
    rating = "Weak" if bits < 40 or pw.lower() in COMMON else "Medium" if bits < 60 else "Strong"
    return rating, round(bits, 1), issues

if __name__ == "__main__":
    pw = sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Password: ")
    r, b, i = analyze(pw)
    print(f"{r} ({b} bits)"); [print(" -", x) for x in i]
