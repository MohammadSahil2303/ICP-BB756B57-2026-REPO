# Optional Project 3 Proposal – Encryption Tool (Project Bank #3)

**Goal:** CLI that encrypts and decrypts files securely, completing the cycle (find exposed services → strong credentials → protect data).

**Plan**
- Library: `cryptography` (no custom crypto). Symmetric: AES-256-GCM (authenticated). Key from passphrase via scrypt (or PBKDF2-HMAC-SHA256 ≥ 600k iterations) with random salt.
- Hybrid mode: RSA-4096 (OAEP) wraps a random AES key for sharing files.
- File format: magic header, version, salt, nonce, ciphertext, tag; chunked streaming for large files.
- Key management: generate/export/import RSA keys, passphrase-protected PEM, no keys in logs or arguments.
- Safety: refuse to overwrite files, verify tag before writing output, constant-time compare.
- Tests: round trip, wrong password, tampered ciphertext, truncated file, large file.
- Deliverables: tool, tests, threat model, report.

**Status:** proposal only; not implemented in this internship.
