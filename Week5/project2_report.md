# Project 2 Report – Password Strength Analyzer

**Tool:** `Week5/password_analyzer/pwcheck.py` (v1 in `Week4/`)

## 1. Problem
Users choose weak, predictable passwords. Composition rules ("one capital, one symbol") do not make `Summer2024!` safe, and naive entropy calculators overrate it.

## 2. Method
1. **Policy checks (regex):** length ≥ 12, lowercase, uppercase, digit, symbol, no edge whitespace.
2. **Theoretical entropy:** `len × log2(charset)` (upper bound for random passwords).
3. **Attacker-model entropy:** dynamic programming finds the cheapest way to build the password from dictionary words (≈12 bits each, +1 capitalised, +1.5 leetspeak), years (6.5 bits), digits (3.3/char), common separators (3), other symbols (5), letters (4.7) and repeats (1). The lower of the two figures is reported.
4. **Pattern detection:** common passwords (also with leetspeak), keyboard walks, sequences, repeated blocks, years. Patterns reduce the estimate.
5. **Crack-time estimate** for throttled online (100/hour), slow offline hash (10⁴/s) and fast offline hash (10¹⁰/s) attacks.
6. **Score 0–100** (`bits/80`), capped for short passwords, and **recommendations**.
7. **Extras:** secure prompt, batch mode, HIBP k-anonymity breach check, passphrase generator using `secrets` (64 bits for 5 words).

## 3. Results
v1 vs final on the same inputs:

| Password | v1 rating | Final score / rating |
|---|---|---|
| `Summer2024!` | Strong (72.3 bits) | 28 / Weak (22.5 bits) |
| `Tr0ub4dor&3` | Strong | 28 / Weak |
| `P@ssw0rd` | Weak | 10 / Very Weak |
| `Xk9#mQ2$vL7!pR` (random) | Strong | 70 / Strong |
| `correct-horse-battery-staple` | Strong | 71 / Strong |

Full batch: `sample_batch.txt`; JSON: `sample.json`. Tests: 10/10 pass, including a regression that predictable "complex" passwords score < 45.

## 4. Limitations
- The dictionary is small (BIP-39 plus about 100 extra words), so an English word outside it is treated as random letters and **overrated**. Production tools (zxcvbn) use tens of thousands of words, names and frequency ranks.
- Crack-time numbers are order-of-magnitude estimates under assumed guess rates.
- A well-known passphrase such as `correct-horse-battery-staple` is still publicly known; the tool rates its structure, not its fame.
- The HIBP breach lookup was written to the public API spec but **not exercised** in the build environment (no outbound access to that service).
- ASCII-focused; no non-English dictionaries.

## 5. Recommendations to users
Prefer long random passphrases, use a password manager, never reuse passwords, enable MFA, check for breaches.
