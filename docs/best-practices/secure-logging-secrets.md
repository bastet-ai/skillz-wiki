# Secure logging: don’t leak secrets

Logging is a **security boundary**. Treat it like one.

Secret leakage to logs is uniquely dangerous because logs are:
- routinely **shipped** off-host (SIEM, cloud log aggregators)
- frequently **retained** long-term
- often **accessible** to many people/roles/tools

## What counts as a “secret”
At minimum:
- passwords
- API keys / access keys
- session tokens / JWTs / refresh tokens
- OAuth authorization codes
- private keys / signing keys
- database connection strings (often contain passwords)
- `Authorization` headers, cookies

## Rules (practical and enforceable)
### 1) Never log secrets at INFO/WARN/ERROR
If you must log something sensitive for debugging:
- require an explicit, time-bounded **debug mode**
- limit to a **single host / single request** via correlation ID
- ensure output is **redacted** and **non-replayable** (hashes/last-4 only)

### 2) Redaction should be centralized
Don’t rely on every engineer remembering to redact.
- Provide a redaction helper for your logging framework.
- Use structured logs and annotate fields as sensitive.
- Apply a second safety net in the log pipeline (agent/collector) if possible.

### 3) Log “what happened”, not “the data”
Prefer:
- a stable identifier (`user_id`, `request_id`, `tenant_id`)
- event metadata (action, outcome, latency)
- safe summaries (counts, sizes)

Avoid:
- full request/response bodies
- full credentials / tokens
- full headers

### 4) Assume logs are breachable
Design so that *if an attacker gets your logs*, they still can’t immediately:
- authenticate
- replay sessions
- pivot to cloud APIs

This implies:
- short TTLs for tokens
- scoped, least-privilege keys
- easy key rotation

## Incident response quick checklist (if secrets hit logs)
1. **Stop the bleeding**: ship a patch to redact/remove logging.
2. **Rotate** impacted secrets (keys, tokens, credentials).
3. **Hunt**: search log stores for leaked values/patterns.
4. **Purge** where feasible (indices, backups, exports).
5. **Prevent recurrence**: add tests/lints + redaction policy gates.

## References / examples
- RustFS credentials in logs (CWE-532): https://github.com/advisories/GHSA-r54g-49rx-98cr
