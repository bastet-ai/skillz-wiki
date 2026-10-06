---
title: "Coraza WAF evasion wave — argument-limit silent drop, multipart truncation, and audit-log forgery (GHSA)"
---

# Coraza WAF evasion wave — argument-limit silent drop, multipart truncation, and audit-log forgery

Coraza (the Go ModSecurity-compatible WAF) published a coordinated trio on 2026-10-06T20:37–20:38Z, all fixed in **v3.8.0**. For an operator this is a fingerprintable, replayable **WAF-evasion playbook against any Coraza-fronted target running the recommended config** — two request-level rule evasions plus a log-forgery primitive. Unlike typical parser advisories, all three ship with working PoCs and the argument-limit advisory includes a measured bypass-rate table.

| Leg | GHSA / CVE | Class | Fixed |
|---|---|---|---|
| Argument-limit silent drop | [GHSA-6r3q-mjv7-xr8m](https://github.com/advisories/GHSA-6r3q-mjv7-xr8m) / CVE-2026-41510 (high) | ARGS rule evasion | 3.8.0 (bug since 3.0.0) |
| Truncated multipart | [GHSA-r3rm-qphw-hh76](https://github.com/advisories/GHSA-r3rm-qphw-hh76) / CVE-2026-41508 | catch-all rule voided | 3.8.0 (since 3.4.0, PR #1453) |
| Native audit-log CRLF | [GHSA-prpw-wwv7-xjjr](https://github.com/advisories/GHSA-prpw-wwv7-xjjr) / CVE-2026-41504 | audit-log forgery | 3.8.0 (since 3.0.0) |

## Leg 1 — Pad past `SecArgumentsLimit` and the payload is silently discarded (CVE-2026-41510)

`AddGetRequestArgument` / `AddPostRequestArgument` / `AddPathRequestArgument` `return` without storing anything once the collection reaches `SecArgumentsLimit` (default **1000**) — no error variable, no transaction flag, **no rule can observe the drop**. Because `ExtractGetArguments` iterates a Go map (randomized order), which arguments survive is non-deterministic: pad the query string with filler parameters and the malicious one may be the one discarded, invisible to every `SecRule` targeting `ARGS`, `ARGS_GET`, or `ARGS_NAMES`.

Measured bypass rate of one `ARGS @contains` deny rule matches the theoretical `(N − limit) / N` model:

| Total args | Bypass rate |
|---|---|
| 1001 | < 0.1% |
| 1100 | 9% |
| 2000 | 53% |
| 10000 | 94% |

Failed attempts are free, so a handful of retries yields near-certain evasion against **any ARGS-targeted CRS rule** — the entire SQLi/XSS/RCE/LFI detection families.

Engine-level differential that makes this a fingerprinting opportunity:

- **ModSecurity v3 has the same silent drop** but ships compensating rule `id:200007` (`SecRule &ARGS "@ge 1000" ... deny,status:400`) in `modsecurity.conf-recommended`, and its ordered splitter makes the **tail** deterministically drop → place the payload first, pad the tail, no retries needed.
- **`coraza.conf-recommended` ships no equivalent rule** → exploitable out of the box.

Two same-class sub-sinks surfaced in the fix PR ([coraza-ghsa-6r3q-mjv7-xr8m#1](https://github.com/corazawaf/coraza-ghsa-6r3q-mjv7-xr8m/pull/1)), both useful pre-3.8.0:

1. The urlencoded **POST** body processor wrote `ARGS_POST` directly with **no limit check at all** — the cap was dead code for urlencoded bodies (also a memory-DoS surface, overlapping GHSA-3ww9-vw83-9w5x; the JSON processor had zero enforcement: a small flat array body like `[1,1,...]` expanded into millions of `ARGS_POST` entries).
2. The cap compared `Len()` = **distinct keys**, not total values: `a=1&a=1&...` ×1,000,000 never tripped the limit and grew ~60 MB of heap per request.

### Validation workflow (authorized targets/labs only)

1. Baseline: `curl '.../?evil=MARKER_XYZ'` → expect 403 from a matching ARGS rule.
2. Coraza check: same request padded to ~10,000 filler params (`p0=0&p1=0&...`) with the marker at random offset, 20–50 retries. Probabilistic 200s ⇒ Coraza ≤3.7.0; deterministic 400 at the limit ⇒ ModSecurity with 200007; deterministic 200 when payload-first/pad-tail ⇒ ModSecurity without 200007.
3. POST variant: urlencoded body with >1000 args — pre-3.8.0 Coraza never drops, so combine POST payload with GET padding to move the payload into the uncapped collection.
4. After fixing, re-verify with the repeated-key shape (`a=1&` ×many) — fix version 3.8.0 added `ARGUMENTS_LIMIT_REACHED` + `Map.TotalValues()`; hand-rolled configs without the compensating rule remain exposed even on patched engines.

## Leg 2 — Truncate the multipart body and rule 200003 never fires (CVE-2026-41508)

Since PR #1453 (v3.4.0), the multipart body processor treats `io.ErrUnexpectedEOF` as benign **and fails to set `MULTIPART_STRICT_ERROR`** (the flag-setting line was dropped when the error-return was removed). A body with no closing boundary, or cut mid-part, returns `nil`: neither `REQBODY_ERROR` (rule 200002) nor `MULTIPART_STRICT_ERROR` (rule 200003) fires — PoC shows HTTP 400-expected requests served 200 with an empty match log.

Why it matters: rule 200003 is Coraza's **only** blanket defense against multipart parser-inconsistency evasions — the class where Coraza's Go `mime/multipart` reader and the backend's parser (PHP/Node/Java) disagree about field boundaries. With the rule voided for any truncated body you regain: smuggling a second field past the truncation boundary that the backend's more permissive parser still extracts, and hiding payload bytes after a malformed `Content-Disposition` the Go reader refuses but the backend accepts.

Probe (lab backends only): send a two-part form with **no trailing boundary**, and a mid-part cutoff (`name="x"\r\n\r\nabc` with no `\r\n`). HTTP 200 + no 200002/200003 audit record ⇒ Coraza 3.4.0–3.7.0. Pair with the usual backend-parser-differential battery to prove the actual field-smuggling effect before claiming bypass.

## Leg 3 — Forge audit-log lines with raw CRLF in the body (CVE-2026-41504)

The default `SecAuditLogFormat Native` writer dumps request body, headers, response bodies, error messages, and matched-rule raw data into the audit log **without escaping `\r`/`\n`**. A urlencoded POST body containing raw CRLF injects structurally valid lines into the single-record audit entry — including fake `--<prefix>-X--` section boundaries and fake `[client "9.9.9.9"]` attribution lines that line-based SIEM ingestion cannot distinguish from genuine content. Triggering audit logging is trivial (send any request matching any audit-logged rule); the forgery is invisible to the WAF itself.

Limits to respect in reporting: the per-transaction boundary prefix is 10 random chars and unpredictable, so forging a *complete separate session* is not proven — integrity of the record the attacker's request lands in is fully compromised. JSON/OCSF audit formats are unaffected (`json.Marshal` escapes).

Red-team framing: treat the WAF audit log as an **attacker-writable file** — this is an anti-attribution / alert-noise primitive (plant misleading client IPs, bury a real match under attacker-controlled noise) for authorized engagements, and for defenders a reason to prefer JSON audit format. Header-vector reachability note: Go `net/http` rejects CRLF-in-header at parse time, so the header legs (Parts B/F) only apply behind `coraza-spoa` (HAProxy), `coraza-proxy-wasm`/Envoy, or custom FFI hosts that forward unvalidated header bytes.

## Durable rules

- **Resource limits without a rule-visible signal are evasion surfaces.** Enumerate every parser path where a cap or error condition results in a silent skip rather than a reject *or* a flag a rule can key on. The bug class = `return` without flag; the audit question = "what variable does a rule read when this path drops?" — if the answer is none, the rule set has a hole.
- **Engine parity ≠ config parity.** The same engine bug (ModSecurity and Coraza both silent-drop) is exploitable only on the engine whose *recommended config* lacks the compensating rule. Fingerprint WAFs by behavioral differential (probabilistic vs deterministic drop), not banner.
- **Truncation as an evasion primitive.** When a parser's error-handling path was intentionally softened (here to support `ProcessPartial`), check whether the *observability flag* was dropped along with the error return. Deliberately incomplete bodies test whether the catch-all malformed-input rule still fires.
- **Cap semantics audit:** per-collection vs aggregate caps, distinct-keys vs total-values counting, and parse-before-cap (memory spent during parsing before any limit runs) are three independent misses the same fix PR had to close — test all three shapes when validating any "limited" parser.
- **Log forgery = input handling at the log writer.** Any sink that interpolates request bytes into a structured, line/boundary-delimited format without escaping is a forgery surface; JSON-encoded sinks are immune by construction.

## Safety notes

All probes belong in authorized labs or customer-approved scopes. Use inert marker strings, benign filler parameters, and your own backend listeners; do not target third-party fronted infrastructure, and do not write forged entries into production logs on engagements without explicit authorization for anti-forensic testing.

## Sources

- [GHSA-6r3q-mjv7-xr8m / CVE-2026-41510](https://github.com/corazawaf/coraza/security/advisories/GHSA-6r3q-mjv7-xr8m) — fix [coraza-ghsa-6r3q-mjv7-xr8m#1](https://github.com/corazawaf/coraza-ghsa-6r3q-mjv7-xr8m/pull/1), release [v3.8.0](https://github.com/corazawaf/coraza/releases/tag/v3.8.0)
- [GHSA-r3rm-qphw-hh76 / CVE-2026-41508](https://github.com/corazawaf/coraza/security/advisories/GHSA-r3rm-qphw-hh76) — fix [f94c81b](https://github.com/corazawaf/coraza/commit/f94c81bec209f658120c418448d0590a549b71df)
- [GHSA-prpw-wwv7-xjjr / CVE-2026-41504](https://github.com/corazawaf/coraza/security/advisories/GHSA-prpw-wwv7-xjjr) — fix [a307932](https://github.com/corazawaf/coraza/commit/a3079325547c7c1e08522aed4d6468f25d080e25)
- Related covered elsewhere: [XSS payload hiding in HTML tag names (WAF bypass)](../methodology/xss-tag-name-payload-hiding-waf-bypass.md)
