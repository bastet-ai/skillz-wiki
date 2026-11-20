---
title: "Coraza WAF evasion wave, argument-limit silent drop, multipart truncation, and audit-log forgery (GHSA)"
---

# Coraza WAF evasion wave (3 GHSAs): argument-limit silent drop

**Wave in one line:** argument-limit silent drop, multipart truncation, and audit-log forgery

Coraza (the Go ModSecurity-compatible WAF) published a coordinated trio on 2026-10-06T20:37-20:38Z, all fixed in **v3.8.0**. For an operator this is a fingerprintable, replayable **WAF-evasion playbook against any Coraza-fronted target running the recommended config**, two request-level rule evasions plus a log-forgery primitive. Unlike typical parser advisories, all three ship with working PoCs and the argument-limit advisory includes a measured bypass-rate table.

| Leg | GHSA / CVE | Class | Fixed |
|---|---|---|---|
| Argument-limit silent drop | [GHSA-6r3q-mjv7-xr8m](https://github.com/advisories/GHSA-6r3q-mjv7-xr8m) / CVE-2026-41510 (high) | ARGS rule evasion | 3.8.0 (bug since 3.0.0) |
| Truncated multipart | [GHSA-r3rm-qphw-hh76](https://github.com/advisories/GHSA-r3rm-qphw-hh76) / CVE-2026-41508 | catch-all rule voided | 3.8.0 (since 3.4.0, PR #1453) |
| Native audit-log CRLF | [GHSA-prpw-wwv7-xjjr](https://github.com/advisories/GHSA-prpw-wwv7-xjjr) / CVE-2026-41504 | audit-log forgery | 3.8.0 (since 3.0.0) |

## Leg 1, Pad past `SecArgumentsLimit` and the payload is silently discarded (CVE-2026-41510)

`AddGetRequestArgument` / `AddPostRequestArgument` / `AddPathRequestArgument` `return` without storing anything once the collection reaches `SecArgumentsLimit` (default **1000**), no error variable, no transaction flag, **no rule can observe the drop**. Because `ExtractGetArguments` iterates a Go map (randomized order), which arguments survive is non-deterministic: pad the query string with filler parameters and the malicious one may be the one discarded, invisible to every `SecRule` targeting `ARGS`, `ARGS_GET`, or `ARGS_NAMES`.

Measured bypass rate of one `ARGS @contains` deny rule matches the theoretical `(N − limit) / N` model:

| Total args | Bypass rate |
|---|---|
| 1001 | < 0.1% |
| 1100 | 9% |
| 2000 | 53% |
| 10000 | 94% |

Failed attempts are free, so a handful of retries yields near-certain evasion against **any ARGS-targeted CRS rule**, the entire SQLi/XSS/RCE/LFI detection families.

Engine-level differential that makes this a fingerprinting opportunity:

- **ModSecurity v3 has the same silent drop** but ships compensating rule `id:200007` (`SecRule &ARGS "@ge 1000" ... deny,status:400`) in `modsecurity.conf-recommended`, and its ordered splitter makes the **tail** deterministically drop → place the payload first, pad the tail, no retries needed.
- **`coraza.conf-recommended` ships no equivalent rule** → exploitable out of the box.

Two same-class sub-sinks surfaced in the fix PR ([coraza-ghsa-6r3q-mjv7-xr8m#1](https://github.com/corazawaf/coraza-ghsa-6r3q-mjv7-xr8m/pull/1)), both useful pre-3.8.0:

1. The urlencoded **POST** body processor wrote `ARGS_POST` directly with **no limit check at all**, the cap was dead code for urlencoded bodies (also a memory-DoS surface, overlapping GHSA-3ww9-vw83-9w5x; the JSON processor had zero enforcement: a small flat array body like `[1,1,...]` expanded into millions of `ARGS_POST` entries).
2. The cap compared `Len()` = **distinct keys**, not total values: `a=1&a=1&...` ×1,000,000 never tripped the limit and grew ~60 MB of heap per request.

### Validation workflow (authorized targets/labs only)

1. Baseline: `curl '.../?evil=MARKER_XYZ'` → expect 403 from a matching ARGS rule.
2. Coraza check: same request padded to ~10,000 filler params (`p0=0&p1=0&...`) with the marker at random offset, 20-50 retries. Probabilistic 200s ⇒ Coraza ≤3.7.0; deterministic 400 at the limit ⇒ ModSecurity with 200007; deterministic 200 when payload-first/pad-tail ⇒ ModSecurity without 200007.
3. POST variant: urlencoded body with >1000 args, pre-3.8.0 Coraza never drops, so combine POST payload with GET padding to move the payload into the uncapped collection.
4. After fixing, re-verify with the repeated-key shape (`a=1&` ×many), fix version 3.8.0 added `ARGUMENTS_LIMIT_REACHED` + `Map.TotalValues()`; hand-rolled configs without the compensating rule remain exposed even on patched engines.

## Leg 2, Truncate the multipart body and rule 200003 never fires (CVE-2026-41508)

Since PR #1453 (v3.4.0), the multipart body processor treats `io.ErrUnexpectedEOF` as benign **and fails to set `MULTIPART_STRICT_ERROR`** (the flag-setting line was dropped when the error-return was removed). A body with no closing boundary, or cut mid-part, returns `nil`: neither `REQBODY_ERROR` (rule 200002) nor `MULTIPART_STRICT_ERROR` (rule 200003) fires, PoC shows HTTP 400-expected requests served 200 with an empty match log.

Why it matters: rule 200003 is Coraza's **only** blanket defense against multipart parser-inconsistency evasions, the class where Coraza's Go `mime/multipart` reader and the backend's parser (PHP/Node/Java) disagree about field boundaries. With the rule voided for any truncated body you regain: smuggling a second field past the truncation boundary that the backend's more permissive parser still extracts, and hiding payload bytes after a malformed `Content-Disposition` the Go reader refuses but the backend accepts.

Probe (lab backends only): send a two-part form with **no trailing boundary**, and a mid-part cutoff (`name="x"\r\n\r\nabc` with no `\r\n`). HTTP 200 + no 200002/200003 audit record ⇒ Coraza 3.4.0-3.7.0. Pair with the usual backend-parser-differential battery to prove the actual field-smuggling effect before claiming bypass.

## Leg 3, Forge audit-log lines with raw CRLF in the body (CVE-2026-41504)

The default `SecAuditLogFormat Native` writer dumps request body, headers, response bodies, error messages, and matched-rule raw data into the audit log **without escaping `\r`/`\n`**. A urlencoded POST body containing raw CRLF injects structurally valid lines into the single-record audit entry, including fake `--<prefix>-X--` section boundaries and fake `[client "9.9.9.9"]` attribution lines that line-based SIEM ingestion cannot distinguish from genuine content. Triggering audit logging is trivial (send any request matching any audit-logged rule); the forgery is invisible to the WAF itself.

Limits to respect in reporting: the per-transaction boundary prefix is 10 random chars and unpredictable, so forging a *complete separate session* is not proven, integrity of the record the attacker's request lands in is fully compromised. JSON/OCSF audit formats are unaffected (`json.Marshal` escapes).

Red-team framing: treat the WAF audit log as an **attacker-writable file**, this is an anti-attribution / alert-noise primitive (plant misleading client IPs, bury a real match under attacker-controlled noise) for authorized engagements, and for defenders a reason to prefer JSON audit format. Header-vector reachability note: Go `net/http` rejects CRLF-in-header at parse time, so the header legs (Parts B/F) only apply behind `coraza-spoa` (HAProxy), `coraza-proxy-wasm`/Envoy, or custom FFI hosts that forward unvalidated header bytes.

## Durable rules

- **Resource limits without a rule-visible signal are evasion surfaces.** Enumerate every parser path where a cap or error condition results in a silent skip rather than a reject *or* a flag a rule can key on. The bug class = `return` without flag; the audit question = "what variable does a rule read when this path drops?", if the answer is none, the rule set has a hole.
- **Engine parity ≠ config parity.** The same engine bug (ModSecurity and Coraza both silent-drop) is exploitable only on the engine whose *recommended config* lacks the compensating rule. Fingerprint WAFs by behavioral differential (probabilistic vs deterministic drop), not banner.
- **Truncation as an evasion primitive.** When a parser's error-handling path was intentionally softened (here to support `ProcessPartial`), check whether the *observability flag* was dropped along with the error return. Deliberately incomplete bodies test whether the catch-all malformed-input rule still fires.
- **Cap semantics audit:** per-collection vs aggregate caps, distinct-keys vs total-values counting, and parse-before-cap (memory spent during parsing before any limit runs) are three independent misses the same fix PR had to close, test all three shapes when validating any "limited" parser.
- **Log forgery = input handling at the log writer.** Any sink that interpolates request bytes into a structured, line/boundary-delimited format without escaping is a forgery surface; JSON-encoded sinks are immune by construction.

## Safety notes

All probes belong in authorized labs or customer-approved scopes. Use inert marker strings, benign filler parameters, and your own backend listeners; do not target third-party fronted infrastructure, and do not write forged entries into production logs on engagements without explicit authorization for anti-forensic testing.

## Sources

- [GHSA-6r3q-mjv7-xr8m / CVE-2026-41510](https://github.com/corazawaf/coraza/security/advisories/GHSA-6r3q-mjv7-xr8m), fix [coraza-ghsa-6r3q-mjv7-xr8m#1](https://github.com/corazawaf/coraza-ghsa-6r3q-mjv7-xr8m/pull/1), release [v3.8.0](https://github.com/corazawaf/coraza/releases/tag/v3.8.0)
- [GHSA-r3rm-qphw-hh76 / CVE-2026-41508](https://github.com/corazawaf/coraza/security/advisories/GHSA-r3rm-qphw-hh76), fix [f94c81b](https://github.com/corazawaf/coraza/commit/f94c81bec209f658120c418448d0590a549b71df)
- [GHSA-prpw-wwv7-xjjr / CVE-2026-41504](https://github.com/corazawaf/coraza/security/advisories/GHSA-prpw-wwv7-xjjr), fix [a307932](https://github.com/corazawaf/coraza/commit/a3079325547c7c1e08522aed4d6468f25d080e25)
- Related covered elsewhere: [XSS payload hiding in HTML tag names (WAF bypass)](../methodology/xss-tag-name-payload-hiding-waf-bypass.md)

## October 8 17:5xZ follow-up: second Coraza tier, six more WAF-vs-backend parser divergences (fixed 3.8.0/3.8.1)

The same product published a second wave on 2026-10-08T17:45-17:52Z. Same invariant as this page's trio, **the WAF and the backend must agree byte-for-byte on what they parsed; every leg below is a disagreement**, but a different mechanism family: normalization/grammar misses rather than silent drops.

| Leg | GHSA | Mechanism | Divergence |
|---|---|---|---|
| JSON key collision hides values from CRS | [GHSA-5gj4-9gm7-2fx2](https://github.com/advisories/GHSA-5gj4-9gm7-2fx2) | Nested JSON → dot-flattened `ARGS_POST` names with **no escaping of dots in literal keys** | `{"account":{"role":"1' OR '1'='1"},"account.role":"safe"}`, both collapse to `json.account.role`, the harmless later value wins in the WAF; backend parsers keep both properties and expose the malicious one. Bypasses the *complete current CRS* (control pair: 949110 blocks, decoy passes). |
| URL-encoded form with a Content-Type parameter skips body inspection | [GHSA-w253-m66g-rx24](https://github.com/advisories/GHSA-w253-m66g-rx24) | Body-processor selection uses **exact string equality** on the whole lowercased header | `Content-Type: application/x-www-form-urlencoded; charset=UTF-8` ≠ `application/x-www-form-urlencoded` ⇒ no ARGS_POST/REQUEST_BODY inspection at all; backend parses normally. (Bundled CRS 901340 forces fallback, engine-parity rule applies.) |
| `filename*` charset restriction = decoy filename | [GHSA-3wr7-993q-jrff](https://github.com/advisories/GHSA-3wr7-993q-jrff) | Go `mime.ParseMediaType` silently drops RFC 5987 extended filename unless charset is exactly `us-ascii`/`utf-8` | `filename*=iso-8859-1''evil.php; filename="safe.gif"`, WAF sees the decoy in `FILES`, backend sees the real name. Same two-filename trick class as the Bricksforge parameter-pair leg. |
| Cookie CTL parser confusion | [GHSA-g4qm-m288-5cp9](https://github.com/advisories/GHSA-g4qm-m288-5cp9) | Cookie trim uses `TrimString` (space/tab only) instead of RFC 6265 C0 exclusion | `a\v=\t'` ⇒ WAF name `a\v` (rule-missed), backend (Werkzeug et al.) trims to `a`. Cookie values are the last commonly-unswept injection carrier. |
| `t:jsDecode` octal off-by-one | [GHSA-pc5q-qfxp-ggqv](https://github.com/advisories/GHSA-pc5q-qfxp-ggqv) / CVE-2026-104774 | Backslash left in the octal buffer ⇒ `ParseInt` fails ⇒ **null byte instead of decoded value** | Every `\ooo`-escaped payload is corrupted *in the WAF only*; browser/backend decodes normally. Any rule relying on jsDecode normalization is blind to JS-octal-encoded syntax. |
| Malformed URI silently empties QUERY_STRING/ARGS_GET | [GHSA-x26q-wvhg-fh4m](https://github.com/advisories/GHSA-x26q-wvhg-fh4m) | `url.ParseRequestURI` error branch (any raw control byte 0x00-0x1F/0x7F) drops the args extraction, the compensating code is **literally commented out** | Path with raw `\n`/`\t` in the query ⇒ WAF sees no GET args, non-net/http integrations + backend still parse them. Commented-out-fallback = grep fingerprint for regression reintroduction. |

Also in-wave, tracked no-publish: deferred multipart fd accumulation, JSON recursion CPU, unbounded-depth gjson state after argument-limit truncation (DoS class; note the last is the *interaction* of this page's Leg 1 with the JSON processor, caps that drop args can reopen depth accounting).

**Updated durable rules for the sweep kit (Coraza ≤3.8.0 / any ModSecurity-compatible engine):**

- **Flattening is collision-prone.** Any WAF/RASP/APM that flattens structured input (JSON→dotted args, multipart→named collections) must be probed with keys that are themselves delimiter-carrying (`a.b`, `a]b`, encoded dots). The decoy-overwrite shape, malicious nested value + harmless flat twin, generalizes past Coraza to any rule engine with key-derived collections.
- **Header-based dispatch on exact string equality breaks the moment a legal parameter is added.** Test every content-type-gated inspection path with the *same body* under `; charset=…` and other registered parameters; selection logic that compares full header strings instead of the parsed media type is the fingerprint to grep.
- **Charset/encoding decorations are parser-differential carriers.** `filename*` charset, JS octal escapes, cookie CTLs, raw control bytes in URIs, four legs, one rule: put *legal-but-unusual* encodings on every carrier and diff what the inspection layer logs against what the backend acts on (the WAF's own audit log is your divergence oracle; see Leg 3 log forgery for when that lies to you).
- **Commented-out error fallbacks survive as behavior.** When reading open-source WAF/proxy code, a commented block beside an error branch is a documented bug, treat `/* ... Variables.RequestUri ... */`-style artifacts as pre-located test cases.

## November 16 follow-up: SamWaf skips the request body entirely for chunked transfers and >=2 KB payloads (CVE-2026-129869 / [GHSA-3rhw-292r-4fv7](https://github.com/advisories/GHSA-3rhw-292r-4fv7), medium, 1.0.128 through 1.3.25-beta.11)

SamWaf (Go WAF, `WafEngine.ServeHTTP`) only inspects request bodies when the transfer encoding is `Content-Length` **and** the body is smaller than 2048 bytes. Anything chunked, anything padded to 2 KB or more, reaches the protected backend **completely uninspected**: SQLi, XSS, command injection, traversal, and upload payloads all pass by adding `Transfer-Encoding: chunked` or appending filler parameters until the body crosses the threshold. Same invariant as this page's Leg 1: **an inspection path with a silent size/encoding gate is an on/off switch the attacker controls**, and unlike Leg 1 there is not even a partial inspection to probabilistically dodge, it is unconditional skip.

- **Transport-shape battery belongs in every WAF sweep, not just payload mutation.** Before mutating a single payload byte, replay the *same proven payload* under four body shapes: (1) plain `Content-Length`, (2) `Transfer-Encoding: chunked` (single chunk), (3) chunked with multiple small chunks, (4) `Content-Length` padded past common inspection caps (2 KB here; sweep 1/2/4/8/16 KB). A WAF that logs the plain request and stays silent on chunked is the fingerprint; the WAF's own log-vs-delivery diff (Leg 3) is the oracle.
- **Threshold-grepping is the white-box twin.** In any proxy/inspector source, grep for body-length constants (`2048`, `MaxBodySize`, `len(body) <`) on the inspection path and ask what happens *above* the threshold: skip-inspect-continue (SamWaf, fail-open) is a bug, reject-413 is a policy. Fail-open-on-oversize is the same taxonomy as the Coraza argument-drop: the safe default when you cannot inspect is to refuse, and silent pass-through is always the vulnerability.
- Validation boundary: your own lab target behind SamWaf <7.8.0/1.3.26, inert canary payloads (SQL comment probes, DOM markers), never live exploits against third-party perimeters.

## November 19 23:1xZ follow-up: Guard Core, the preprocessing pipeline deletes the bytes two built-in detectors require, and an unvalidated XFF becomes a Redis KEYS glob (CVE-2026-129303 / [GHSA-w7wg-6q7v-44f2](https://github.com/advisories/GHSA-w7wg-6q7v-44f2) low + CVE-2026-129304 / [GHSA-gm9r-hvc9-96gv](https://github.com/advisories/GHSA-gm9r-hvc9-96gv) medium, guard-core < 3.13.0)

Guard Core (the detection engine behind fastapi-guard) ships a default "enhanced" mode that is a textbook instance of this page's standing invariant, **preprocessing that transforms away what the detector was written to match**, plus a header-trust leg that turns rate-limit bookkeeping into a shared-state attack primitive.

**Leg 1, whitespace-collapse kills the CRLF-anchored detectors (CVE-2026-129303).** `ContentPreprocessor.preprocess()` runs `re.sub(r"\s+", " ", content)` before pattern matching in default enhanced mode. Two built-in detectors are *structurally unmatchable* afterward regardless of input: http_split (`[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)`) and cmd_injection (`\n\s*(?:bash|sh|...)\s+-c\b`) both require a literal CR or LF that no longer exists. The downstream app still receives the **raw** value with CRLF intact (Starlette percent-decodes `%0d%0a` in query params before the adapter hands them to the scanner), so `?q=value%0d%0aHTTP%2F1.1+200+OK%0d%0aSet-Cookie%3A+pwned%3D1` returns 200-missed while `' OR 1=1--` correctly 400s. The legacy mode (no `SecurityConfig` detection attributes) skips preprocessing and catches the same payload, so the gap is specific to the stock-config pipeline. Every other preprocessing step (URL/HTML/hex/base64 decode) transforms *toward* attacker intent; the whitespace collapse is the one step that strips signal the rules depend on.

**Leg 2, unvalidated XFF becomes a Redis key and a KEYS glob (CVE-2026-129304).** `_extract_from_forwarded_header()` returns the selected `X-Forwarded-For` entry with **no `ipaddress` validation** when the peer is a trusted proxy; the arbitrary string flows into `BehaviorTracker`, which interpolates it verbatim into a Redis key name and a `KEYS` glob pattern. Three operator-grade effects, verified with a fake-Redis harness: (1) `XFF: *` makes the behavioral-usage counter glob match **every client's keys** for the endpoint, so an attacker trips a victim's rate-limit/ban rule on its first request (counter contamination is bidirectional: you can poison or bypass thresholds); (2) an embedded `:` shifts which key segment parses as the timestamp, corrupting window math; (3) rotating arbitrary XFF strings multiplies distinct keys without bound while each request issues a blocking O(keyspace) `KEYS` scan on the shared Redis. The ban path then passes the non-IP string to `ipaddress` validation which raises uncaught, 500-ing the request.

Operator rules:

1. **Detector-deadness probe battery.** For any inline WAF/RASP in front of your target (or your own stack, blue-side audit), test each detection class through *every* framework-level normalization that runs before inspection: percent-decode-to-control-byte, whitespace variants (`%09`, `%0b`, `%0c`, `%0d%0a`, `%a0`), and double-encoding. A payload class that passes only when it contains a character the preprocessor collapses is the fingerprint of Leg 1. Cross-check against the vendor's legacy/default mode if one exists: mode-dependent detection equality is itself the report.
2. **A header that becomes a cache/keyspace key is a cross-tenant primitive.** Any per-client bookkeeping keyed on a client-influenced string (rate limits, behavior trackers, abuse counters, feature flags) needs the same validation as an IP parser. Probe battery: `X-Forwarded-For: *`, `?`, `**`, `..`, `:`-bearing, and empty-string variants; then watch whether your requests move *other* clients' counters (trip a threshold you did not consume) or whether responses 500 on the ban path (uncaught validator = confirmation you escaped the IP type).
3. **Fix-shape fingerprint:** 3.13.0 added `ipaddress` validation on the extracted value; when auditing sibling Python guard stacks, grep for header extraction functions that `return` without a type/parse call, and for `KEYS`/`SCAN` calls with f-string patterns. `KEYS` with attacker-interpolated pattern is both a security bug and a Redis-wide DoS lever.
Validation boundary: your own lab behind fastapi-guard/guard-core <3.13.0, inert canaries (Set-Cookie marker lines, SQL comment probes), disposable Redis; never steer shared rate-limit state on third-party perimeters.
