# 2026-02-02 — Mailpit SMTP header injection via regex bypass (GHSA-54wq-72mp-cq7c)

## Summary

GitHub reviewed an advisory for **SMTP header injection / message corruption** in **Mailpit** (Go).

- Advisory: https://github.com/advisories/GHSA-54wq-72mp-cq7c
- Impact (per advisory): attacker-controlled **carriage return** in `MAIL FROM` / `RCPT TO` can corrupt generated headers and may enable **header injection** in downstream consumers.
- Root cause: a **denylist regex** intended to exclude vertical whitespace uses `\v` **inside a character class** (`[^<>\v]`), but in Go/RE2 `\v` inside `[...]` matches only **vertical tab** (`0x0b`), not `\r`/`\n`.

## Why this matters

CRLF (and even “bare CR”) problems recur across ecosystems:

- what looks like “just formatting” becomes **security boundary break** when a downstream parser treats attacker-controlled line breaks as new headers;
- even when immediate injection is blocked at a network layer, writing raw attacker-controlled control characters to storage can create **corrupt artifacts**, bypass validations in later pipelines, or trigger parsing differentials.

Mailpit is a testing tool, but teams routinely:

- export `.eml` files,
- relay messages,
- or rely on Mailpit behavior as a proxy for “what is safe in prod”.

## What to do (durable guidance)

1. **Treat SMTP envelope addresses as hostile input**
   - Reject **CTLs** (`0x00–0x1F` and `0x7F`) in `MAIL FROM` / `RCPT TO`.
   - Specifically reject `\r` and `\n` even if your socket read path “usually” blocks `\n`.

2. **Prefer parsing over regex**
   - For email-ish strings, prefer a real parser (`net/mail` in Go, robust libraries elsewhere) + explicit validation rules, rather than hand-rolled regex.

3. **If you must regex, avoid denylists and escape gotchas**
   - Prefer an **allowlist** for the characters you expect.
   - If you intend to ban line breaks, ban them explicitly (e.g., `\r` and `\n`) and test those exact bytes.

4. **Defend against “format differentials” in pipelines**
   - Ensure exported messages are normalized to **CRLF** and contain no bare CR.
   - Add regression tests that round-trip through your downstream consumers (mail clients, scanners, gateways) to detect header injection or corruption.

## Related Wisdom

- [SMTP/CRLF header injection hardening](../best-practices/smtp-header-injection.md)
