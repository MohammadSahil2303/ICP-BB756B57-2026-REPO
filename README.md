# ICP-BB756B57-2026-REPO

**InternCareerPath – Cyber Security Self-Learning Internship (6 weeks)**
Portal ID: `ICP-BB756B57-2026` · Repo ID: `REPO-0FAAE88A`

| Project | Tool | Where |
|---|---|---|
| 1 – Network Port Scanner | `portscan.py` (TCP connect, UDP, optional Scapy SYN, banner grabbing, JSON/CSV) | `Week2/`, `Week3/` |
| 2 – Password Strength Analyzer | `pwcheck.py` (policy, entropy, dictionary/pattern model, crack-time, HIBP, generator) | `Week4/`, `Week5/` |
| 3 – Encryption Tool (optional) | Proposal only | `Week5/project3_proposal.md` |

## Structure
```
Week1/  fundamentals, lab setup, project selection
Week2/  Project 1 development (port_scanner/, testing methodology, progress notes)
Week3/  Project 1 validation, documentation, final report
Week4/  Project 2 development (v1, technical notes)
Week5/  Project 2 completion (final tool, tests, report) + Project 3 proposal
Week6/  Final report, portfolio, LinkedIn post, ethics statement
```

## Quick start
```bash
python3 Week2/port_scanner/portscan.py 127.0.0.1 -p top
python3 Week5/password_analyzer/pwcheck.py            # prompts securely
python3 Week5/password_analyzer/pwcheck.py -g 5       # passphrase generator
python3 -m unittest discover -s Week2/port_scanner    # 5 tests
python3 -m unittest discover -s Week5/password_analyzer  # 10 tests
```
Python 3.9+, standard library only (Scapy optional for `--syn`).

## Ethics
Everything was tested on `127.0.0.1` or systems I own. The scanner refuses public
addresses unless `--i-have-permission` is passed. Passwords are never logged or stored.
