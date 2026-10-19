# Final Report – Cyber Security Self-Learning Internship

**Portal ID:** ICP-BB756B57-2026 · **Repo:** ICP-BB756B57-2026-REPO · **Duration:** 6 weeks

## Summary
Two complete projects: a Network Port Scanner and a Password Strength Analyzer, with tests, sample output and reports. A third (Encryption Tool) is proposed.

| Requirement | Evidence |
|---|---|
| ≥ 2 completed projects | `Week3/port_scanner`, `Week5/password_analyzer` |
| Professional security reports | `Week3/project1_report.md`, `Week5/project2_report.md` |
| Ethical conduct | loopback-only testing; ethics gate in scanner; no password logging |
| Weekly deliverables | Week1–Week6 folders |

## Week by week
1. Fundamentals, lab setup, project selection.
2. Scanner built (connect/UDP/SYN, banners), testing methodology, progress notes.
3. Validation (4/4 known listeners, 2 s full sweep), documentation, report.
4. Analyzer v1; discovered that charset entropy rates `Summer2024!` Strong.
5. Attacker-model entropy, pattern detection, crack times, generator; 10 tests; report; Project 3 proposal.
6. Portfolio and submission.

## What I learned
- TCP/UDP scan semantics and why UDP is ambiguous.
- Testing a security tool against ground truth, and reading unexpected results (extra listeners) without guessing.
- Entropy formulas assume randomness; modelling the attacker matters more than counting character classes.
- Defence follows from attack: each tool output maps to a concrete mitigation.

## Honest limitations
Nmap cross-check, SYN mode and the HIBP lookup were not exercised in the build environment; the analyzer's dictionary is small. Details in each project report.

## Next steps
Encryption tool (Project 3), IPv6/CIDR scanning, larger password dictionary, then Security+ preparation.
