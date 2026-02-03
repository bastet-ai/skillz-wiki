# 2026-02-03 — RustFS logs credentials in plaintext (GHSA-r54g-49rx-98cr)

**Summary:** RustFS logged sensitive credential material (access keys, secret keys, session tokens) at **INFO** level, resulting in plaintext secrets being written to logs and potentially forwarded to log aggregation systems.

- **Component:** RustFS
- **Impact:** Secret leakage via logs → account/session compromise
- **Class:** CWE-532 (Insertion of Sensitive Information into Log File)

## Why this matters (durable lesson)
Secrets leaked to logs tend to become **high-latency compromises**:
- Logs are copied, shipped, and retained.
- Access control to logs is often broader than access to the production service.
- A single accidental log line can outlive key rotation unless you actively hunt and purge.

## Defensive actions
1. **Redact by default (central policy, not “best effort”)**
   - Create a shared redaction helper and require it for structured logging.
   - Explicitly mark fields as sensitive (`secret`, `token`, `password`, `key`, `Authorization`, cookies).
   - Ensure redaction happens **before** log shipping.

2. **Treat log access as production access**
   - Restrict who can read logs.
   - Separate tenant/customer logs.
   - Alert on access to sensitive log indices.

3. **Reduce exposure window**
   - Rotate impacted credentials.
   - Search centralized logs for leaked patterns and purge where possible.
   - Consider short TTLs for session tokens.

4. **Patch / upgrade**
   - Upgrade to **1.0.0-alpha.82** (per advisory) or later.

See also: [Secure logging: don’t leak secrets](../best-practices/secure-logging-secrets.md).

## References
- GitHub Advisory: https://github.com/advisories/GHSA-r54g-49rx-98cr
