# 2026-02-03 — `url-parse` multiple URL parsing issues (multiple GHSAs; upgrade)

## Executive summary
GitHub’s advisory feed surfaced updates to multiple historical issues in the popular npm package `url-parse`.

**Practical guidance:** if you depend on `url-parse`, **upgrade** to a fixed version and **avoid using non-standard URL parsers for security decisions** (allow/deny lists, protocol checks, SSRF protections, open-redirect protections). Prefer the platform’s **WHATWG `URL`** parser.

## What’s the risk?
Several of the reported issues are the kind that become security bugs *in your application* when you rely on URL parsing/normalization to:

- enforce allowed hostnames/schemes (SSRF defenses)
- block `javascript:` / dangerous schemes (XSS/open redirect chains)
- implement allow/deny lists or safe-redirect logic

Different parsers may disagree on how to interpret ambiguous input (control characters, backslashes, missing slashes, etc.). If you validate with one parser but a client/server later interprets the URL differently, you can get a bypass.

## Affected component
- npm: `url-parse`

## Recommended actions
1. **Upgrade `url-parse`** to a fixed version (see advisory pages below for exact version ranges).
2. **If you do security-sensitive URL decisions, switch to WHATWG `URL`:**
   - Node.js: `new URL(input)`
   - Browsers: `new URL(input, base)`
3. **Normalize + validate defensively** (especially for SSRF / redirects):
   - Reject non-`http:`/`https:` schemes explicitly.
   - Enforce an allowlist on `hostname` *after* parsing.
   - For redirects: resolve against a fixed base and compare `origin`.
   - Strip / reject leading control characters and other ambiguous encodings.

## References (GitHub Advisories)
- GHSA-46c4-8wrp-j99v — Improper validation/sanitization in `url-parse`
  - https://github.com/advisories/GHSA-46c4-8wrp-j99v
- GHSA-hh27-ffr2-f2jc — Open redirect in `url-parse`
  - https://github.com/advisories/GHSA-hh27-ffr2-f2jc
- GHSA-9m6j-fcg5-2442 — Path traversal / misparse issue in `url-parse`
  - https://github.com/advisories/GHSA-9m6j-fcg5-2442
- GHSA-jf5r-8hm2-f872 — Leading control characters not stripped
  - https://github.com/advisories/GHSA-jf5r-8hm2-f872
