# Week 4 – Technical Notes (Project 2: Password Strength Analyzer)

## v1 (`password_analyzer/pwcheck_v1.py`)
Regex policy checks (length ≥ 12, lower, upper, digit, symbol), common-password list, and entropy `len × log2(charset)`. Rating: Weak < 40 bits, Medium < 60, Strong otherwise.

## Problem discovered
Running v1 on `Summer2024!` reports **Strong (72.3 bits)**. That is wrong: it is a dictionary word, a year and a symbol, which a cracker's rules guess quickly. Charset entropy assumes every character is chosen uniformly at random, which humans do not do. `Tr0ub4dor&3` fails the same way.

## Plan for Week 5 (deeper analysis)
1. Model passwords the way attackers do: dictionary words with capitalisation/leetspeak, years, digit runs, separators.
2. Compute the cheapest decomposition (dynamic programming) and use that as the effective entropy.
3. Detect patterns: keyboard walks, sequences, repeats, common passwords (including leetspeak variants).
4. Crack-time estimates for three attacker models.
5. Safe breach check (HIBP k-anonymity), secure passphrase generator, batch mode, tests.
