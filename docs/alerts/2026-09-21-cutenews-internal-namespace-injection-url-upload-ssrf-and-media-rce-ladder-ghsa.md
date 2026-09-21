# CuteNews internal-variable injection, URL-upload SSRF, and media-panel upload ladder

Source: hourly offensive-security scan, 2026-09-21. Primary entries: GitHub Advisory Database [GHSA-mwgw-rr28-m856](https://github.com/advisories/GHSA-mwgw-rr28-m856) / CVE-2026-36471 (`__post_data` deserialization into internal request variables), [GHSA-qqh7-w389-w2hg](https://github.com/advisories/GHSA-qqh7-w389-w2hg) / CVE-2026-36469 (Media Manager `upload_from_inet` SSRF), [GHSA-2j38-m62m-3qch](https://github.com/advisories/GHSA-2j38-m62m-3qch) / CVE-2026-36467 (unrestricted dangerous-type upload in `core/modules/media.php`, CVSS 7.2), and the adjacent unauthenticated reflected-XSS records [GHSA-qp92-vrxr-34w8](https://github.com/advisories/GHSA-qp92-vrxr-34w8) / CVE-2026-36468, [GHSA-29r2-83fr-44fv](https://github.com/advisories/GHSA-29r2-83fr-44fv) / CVE-2026-36470, [GHSA-9w6g-j664-2ggg](https://github.com/advisories/GHSA-9w6g-j664-2ggg) / CVE-2026-36472 (all CuteNews 2.1.2).

CuteNews is a legacy flat-file PHP CMS. This wave is durable not because of the product but because it packages three reusable bug-hunting patterns: **caller-supplied keys colliding with the framework's internal variable namespace**, **a "fetch this URL for me" admin feature as a standalone SSRF leg**, and **the media panel as a login-to-RCE rung once you have any low-privilege account**.

## Advisory table

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-mwgw-rr28-m856](https://github.com/advisories/GHSA-mwgw-rr28-m856) / CVE-2026-36471 | `cn_parse_url()` deserializes the base64 PHP-serialized `__post_data` POST parameter and merges the result into internal request variables — including internal-name keys such as `__referer` | Remote parameter injection into the app's internal request state; no auth noted. Enumerate which internal variables the merge overwrites, then trace each one to its sinks (this app renders `__referer` back to the `msg_info` page per CVE-2026-36472). |
| [GHSA-qqh7-w389-w2hg](https://github.com/advisories/GHSA-qqh7-w389-w2hg) / CVE-2026-36469 | Media Manager "Upload by URL" (`upload_from_inet`, `core/modules/media.php`) fetches an attacker-supplied URL server-side | Standalone SSRF leg reachable from an admin-panel feature — enumerate URL-ingest features separately from input validators. |
| [GHSA-2j38-m62m-3qch](https://github.com/advisories/GHSA-2j38-m62m-3qch) / CVE-2026-36467 | `core/modules/media.php` accepts dangerous file types from any account with Media Manager access → web-context code execution | Login-to-RCE rung: any account tier that reaches the media panel is effectively an RCE candidate; map which roles get Media Manager by default. |
| [GHSA-qp92-vrxr-34w8](https://github.com/advisories/GHSA-qp92-vrxr-34w8) / CVE-2026-36468 | Unauthenticated reflected XSS via an arbitrarily named URL parameter whose *key* contains URL-encoded markup | Parameter **names** are output too — echo-back reflection sweeps must fuzz keys, not just values. |
| [GHSA-29r2-83fr-44fv](https://github.com/advisories/GHSA-29r2-83fr-44fv) / CVE-2026-36470 | `Referer` header copied unescaped into the `index.php` POST response | Legacy flat-file apps trust "browser-only" headers; include Referer/User-Agent in the reflection battery for POST flows. |
| [GHSA-9w6g-j664-2ggg](https://github.com/advisories/GHSA-9w6g-j664-2ggg) / CVE-2026-36472 | `__referer` rendered as an unsanitized clickable link on `msg_info` — `javascript:` URI executes in an authenticated session | Closes the loop with CVE-2026-36471: the injected internal variable has an authenticated-context render sink, turning blind state injection into session XSS. |

## Why it matters for operators

1. **Internal-name parameter collision is its own finding class.** The app keeps internal request state in `__`-prefixed variables and then merges *deserialized caller input* into that same namespace. Sweep any legacy PHP/ASP app for: keys with a reserved prefix (`__`, `_`, dot-prefix), request-merge helpers (`parse_str` without a target array, `extract()`, `array_merge($internal, $userInput)`), and double-serialized channels (base64+serialize inside a normal POST field). Same family as the Laravel `_method`, Spring `class.*`, and Ruby `__send__` collisions — the fix shape is a denylist; the finding is that the merge is name-blind.
2. **Prove injection→sink chains, not just injection.** The CuteNews chain is `__post_data` → overwrite `__referer` → `msg_info` renders it as a live link → `javascript:` executes in the admin/authenticated session. When you find an internal-state write, enumerate every read of that variable before concluding low severity; a blind state write plus an escaped-looking-but-link-rendered sink is a session-level XSS.
3. **"Upload by URL" features are SSRF even when inputs validate everything else.** Media/import/avatar/sitemap fetchers are separate outbound legs; test them with owned callbacks after the main input validators pass — the validator-negative is not an SSRF-negative.
4. **Flat-file CMS role models leak code-exec reach.** With unrestricted media upload gated only on "can see the media panel," enumerate default role→panel mappings (install docs, config files like `users.php` when in-scope) — a low tier that reaches the panel is an RCE candidate, worth reporting as the ladder not just the XSS.

## Replayable validation boundaries (authorized labs / owned instances only)

1. Version-fingerprint first: confirm CuteNews ≤ 2.1.2 from the readme/`data` paths before any active test; these are fixed-in-later records and a patched target invalidates the whole battery.
2. `__post_data` proof: submit a base64 PHP-serialized array setting only a marker internal key (e.g. an innocuous request variable) and observe the marker's effect in the next response/redirect; never chain to file writes on a shared host.
3. SSRF proof: owned HTTP callback URL in Upload-by-URL; record final destination, response-length oracle, and whether the fetched bytes land in the media directory (that makes it a read primitive, not just a ping).
4. Upload proof: lab-only account, benign canary with a server-executable extension, stop at listing the stored path and correct removal; never leave or serve executable content.
5. XSS proofs: inert structural canaries (`<img onerror=console.log>`-class markers) in parameter *keys*, the Referer header, and an injected `__referer` value; four-stage fidelity (submitted → stored → served → DOM) per the media-asset XSS precedent.

## Reporting heuristics

- Name the leg precisely: **name-blind internal-namespace merge**, **URL-ingest SSRF leg**, **role-gated-only dangerous-type upload**, **parameter-name reflection**, **header reflection on POST flow**, **injected-state → render-sink chain**.
- Report the internal state write as its own finding with the enumerated read sinks; the XSS is the proof-of-impact, not the vulnerability class.
- Keep all evidence synthetic: marker keys, owned callbacks, lab accounts, removable canary files. No real users' sessions, no production uploads.

Related pages: the [Sept 18 WordPress core page](2026-09-18-wordpress-core-7-1-1-parser-xmlrpc-and-object-scope-boundaries-ghsa.md) (parameter-ABSENT and alternate-surface siblings), the [Aug 25 Grav Flex handler page](2026-08-25-grav-sandbox-escape-and-privilege-host-origin-boundaries-ghsa.md) (flat-file CMS internals as attack surface), and the [Sept 20 media-pipeline page](2026-09-20-media-pipeline-edge-surfaces-filename-shellout-metadata-xxe-author-template-rce-ghsa.md) (upload/validation/storage multi-leg evidence).
