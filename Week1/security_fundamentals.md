# Week 1 – Security Fundamentals (research notes)

**CIA triad.** Confidentiality (only authorised people read data), Integrity (data is not altered unnoticed), Availability (systems work when needed). The port scanner supports attack-surface review; the password analyzer protects the confidentiality of accounts.

**TCP/IP and ports.** TCP uses a three-way handshake (SYN, SYN-ACK, ACK). A *connect scan* completes it; a *SYN scan* sends SYN, reads the reply and resets without finishing. Open = SYN-ACK, closed = RST, filtered = silence or ICMP unreachable. UDP has no handshake: silence means `open|filtered`, an ICMP port-unreachable means closed.

**Reconnaissance.** Attackers enumerate hosts, ports and service versions before exploiting. Defenders run the same scans to find forgotten services (Telnet, exposed RDP/SMB, unauthenticated Redis/MongoDB).

**Authentication and password security.** Attacks: brute force, dictionary, credential stuffing (reused leaked passwords), rainbow tables. Defences: length, salted slow hashes (bcrypt/scrypt/Argon2), MFA, breach checking, password managers. `length × log2(charset)` is only a valid entropy for *randomly* chosen characters; human-chosen passwords follow patterns and are far weaker. NIST SP 800-63B favours length and blocklists over composition rules.

**OWASP Top 10 / threat modelling (overview).** Broken access control, cryptographic failures, injection, insecure design, misconfiguration, vulnerable components, authentication failures, integrity failures, logging failures, SSRF. STRIDE for threat modelling.

**Legal and ethics.** Unauthorised scanning or access can violate computer-misuse law (India IT Act s.43/66, US CFAA, UK CMA). Test only what I own or have written permission to test.

**References:** NIST SP 800-63B, OWASP Top 10, Nmap Network Scanning (nmap.org/book), RFC 793 (TCP), RFC 768 (UDP), Have I Been Pwned API docs.
