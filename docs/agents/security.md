# Security

OWASP-oriented review of the **diff** (Top 10, API Top 10, file-upload cheat sheet). Lab prototype: no production auth required, but do not add new holes (path traversal, unbounded upload, CORS `*` + credentials, secrets in git).

**Must not:** disable checks “for the demo”; log full PCAP payloads into prompts as if they were trusted instructions.
