# Flask-Security, FileBrowser, and Drupal boundary batch

Source: GitHub Security Advisories REST fallback and CISA KEV, published/updated 2026-05-22.

This batch is durable because it turns fresh identity, public-share filesystem, and exploited CMS SQL-injection advisories into operator checks for reauthentication freshness bypass, path-normalization order drift, and database-abstraction SQLi impact validation. Use only in authorized lab or scoped assessment environments.

## What changed

- **Flask-Security-Too OAuth reauthentication freshness bypass** — [GHSA-97r5-pg8x-p63p](https://github.com/advisories/GHSA-97r5-pg8x-p63p) / CVE-2026-46715: version 5.8.0 can mark the current session as freshly reauthenticated after the OAuth callback verifies an OAuth identity belonging to a different Flask-Security user. The advisory reproduced the issue against `/change-username`; the important boundary is stale authenticated session plus attacker-controlled OAuth identity becoming sufficient for freshness-protected actions.
- **FileBrowser Quantum public-share path traversal** — [GHSA-qqqm-5547-774x](https://github.com/advisories/GHSA-qqqm-5547-774x): `publicPatchHandler` joins attacker-controlled `items[].fromPath` and `items[].toPath` with the trusted share path before downstream sanitation. Because `filepath.Join` collapses `..` segments before the sanitizer sees them, a public share link with `AllowModify=true` can move, copy, or rename files outside the shared directory but inside the share owner's source root.
- **Drupal Core SQL injection in database abstraction API** — [CVE-2026-9082](https://nvd.nist.gov/vuln/detail/CVE-2026-9082), added to [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) on 2026-05-22: Drupal Core SQL injection can enable privilege escalation and remote code execution through specially crafted requests that reach vulnerable database-abstraction API usage. NVD lists affected ranges from 8.9.0 before 10.4.10, 10.5.x before 10.5.10, 10.6.x before 10.6.9, 11.0.x before 11.1.10, 11.2.x before 11.2.12, and 11.3.x before 11.3.10.

Tracked but not promoted as primary operator guidance this pass: [GHSA-7m8f-hgjq-8gc9](https://github.com/advisories/GHSA-7m8f-hgjq-8gc9) / aiosend pre-auth webhook deserialization DoS and [GHSA-q8mj-m7cp-5q26](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) / qs stringify DoS, both availability/resource-only without a reusable exploit-path lesson for this wiki's current taxonomy.

## Operator triage

1. **Flask-Security:** fingerprint Flask apps using Flask-Security-Too 5.8.0, OAuth login or reauthentication, and freshness-protected routes such as username, email, password, MFA, API-token, or account-linking changes. Confirm whether stale-session reauth is enforced through OAuth callbacks rather than password-only prompts.
2. **Flask-Security session control:** map whether an attacker can operate a victim's already-authenticated stale session in the target model: shared kiosk/browser, session fixation, delegated browser automation, OAuth login CSRF, or other scoped conditions. Do not overstate impact if the assessment cannot explain stale-session control.
3. **FileBrowser Quantum:** enumerate public share links that expose modification actions. Record share root, `AllowModify`, whether PATCH is reachable without login, and whether move/copy/rename operations are enabled for shared content.
4. **FileBrowser path handling:** test canonicalization order with harmless marker filenames containing `../` segments in `items[].fromPath` or `items[].toPath`. Capture whether resulting operations resolve outside the public share directory while staying inside the owner's configured source root.
5. **Drupal:** identify Drupal Core version ranges, public modules or endpoints that invoke database-abstraction API query construction with user-controlled input, and whether the deployment exposes authenticated or unauthenticated request paths matching the vendor advisory prerequisites.
6. **Drupal exploitation evidence:** because KEV confirms active exploitation but public details may be limited, separate version/exposure proof from payload claims. Treat third-party PoCs as untrusted until reproduced in an isolated Drupal lab matching the affected range.

## Replayable validation boundaries

- **Flask-Security freshness proof:** in a lab app with two users and OAuth enabled, authenticate as victim, let the session become stale, then complete the reauth OAuth callback using an OAuth account linked to the attacker user. Vulnerable result: the victim session's freshness timestamp updates and a freshness-protected action proceeds. Keep the action to a benign marker route or a reversible username change.
- **FileBrowser traversal proof:** create a lab source root with `shared/marker.txt` and `outside-share/canary.txt`, then expose only `shared/` through a public share with modify permission. Send a public PATCH move/copy/rename using `../outside-share/canary-copy.txt` as the destination. Vulnerable result: the operation affects the sibling path even though the share UI boundary was `shared/`.
- **Drupal SQLi proof:** use a disposable Drupal install in an affected version range and a test module or route that reaches the vulnerable database-abstraction API pattern. Prove impact with a single boolean, version marker, or lab-only row read before attempting privilege-escalation or code-execution chains. Do not test active production Drupal instances with destructive SQL or credential dumping.

## Reporting heuristics

- Frame Flask-Security findings as **reauthentication subject confusion**: the OAuth identity resolved during freshness verification must match the current session user, not merely any valid local user.
- Frame FileBrowser findings as **canonicalization-before-sanitization path drift**: the public-share boundary is checked after `filepath.Join` has already hidden traversal segments.
- Frame Drupal findings as **database-abstraction SQLi with confirmed exploitation pressure**: include version range, reachable request path, affected query construction context, one minimal marker proof, and the KEV date. Avoid turning the report into a patch-management alert; the operator value is the exploit-path boundary and validation evidence.
- Keep artifacts minimal and redacted: OAuth callback/request logs, route/freshness proof, public-share PATCH request/response, filesystem marker evidence, Drupal version proof, and a single benign SQL marker. Do not include real account changes, sensitive file contents, user hashes, or production database extracts.
