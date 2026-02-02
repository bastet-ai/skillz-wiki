# SMTP header injection (CRLF) — durable defenses

## The pattern

A common vulnerability class is **header injection** (often “CRLF injection”): attacker-controlled input is placed into a header-like context, and an injected line break causes the parser to treat the remainder as a new header.

This shows up in:

- SMTP (`MAIL FROM`, `RCPT TO`, message headers)
- HTTP response splitting (`\r\n` in headers)
- CSV/TSV export pipelines (formula injection has similar “downstream interpreter” properties)
- log ingestion pipelines (multi-line confusion)

## What breaks

- **Bare CR** (`\r` without `\n`) can be especially dangerous because:
  - some network readers block `\n` but allow `\r`;
  - many text tools and parsers treat bare CR as a line break anyway.

- **Regex-based validation** often fails due to:
  - denylist logic (“everything except…”) that forgets a control character;
  - engine-specific escaping semantics (e.g., Go/RE2 `\v` behavior differs inside `[...]`).

## Durable guidance

### 1) Boundary rule: reject control characters

At all ingress points for header-ish fields, reject:

- ASCII control chars: `0x00–0x1F` and `0x7F`
- plus, explicitly, any Unicode line separators if your stack can accept them (`U+2028`, `U+2029`).

For email envelope/header contexts, this is almost always the correct default.

### 2) Prefer parsing + structured formatting

- Use a real parser for the protocol’s grammar, then **re-emit** using a trusted formatter.
- Avoid concatenating raw user strings into header lines.

### 3) If you must validate with regex, test bytes not intentions

- Prefer **allowlists** (what you accept), not denylists (what you block).
- Add unit tests for these exact payloads:
  - `"A\rB"`
  - `"A\nB"`
  - `"A\r\nB"`
  - `"A\x00B"`
  - `"A\u2028B"` (if Unicode is in play)

### 4) Normalize output, not just input

Before exporting, relaying, or storing messages/headers:

- normalize line endings to `\r\n` for SMTP/Internet Message Format;
- ensure no bare CR remains;
- ensure line folding rules are followed (if applicable).

## Example: a common validation footgun (Go/RE2)

In Go’s `regexp` (RE2), `\v` *inside* a character class (`[...]`) matches only **vertical tab** (`0x0b`), not all vertical whitespace. If you intended to block CR/LF, you must block `\r` and `\n` explicitly (and you should still unit-test them).
