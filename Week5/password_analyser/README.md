# pwcheck.py – Password Strength Analyzer

```bash
python3 pwcheck.py                       # secure prompt (no echo, not in shell history)
python3 pwcheck.py 'Summer2024!' --json  # machine-readable
python3 pwcheck.py -f sample_passwords.txt   # batch, masked output
python3 pwcheck.py -g 5                  # 5-word passphrase + true entropy
python3 pwcheck.py 'x' --breach          # HIBP k-anonymity (needs internet)
```
Needs `wordlist.txt` (BIP-39 English list, 2048 words) beside the script. Tests: `python3 -m unittest` (10 tests). Standard library only.
Passwords are never logged or written to disk; the breach check sends only the first 5 characters of the SHA-1 hash.
