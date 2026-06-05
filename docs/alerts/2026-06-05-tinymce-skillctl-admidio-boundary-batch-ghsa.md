# TinyMCE nested-SVG, skillctl path-safety, and Admidio export-CSRF boundaries

Source: GitHub Security Advisories REST API, published/updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **rich-text sanitizer namespace confusion**, **agent-skill library path traversal and symlink exfiltration**, and **admin-session CSRF against sensitive key-export actions**. Use the workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **TinyMCE nested-SVG sanitizer bypass** — [GHSA-mh5m-5hw4-5c69](https://github.com/advisories/GHSA-mh5m-5hw4-5c69) / CVE-2026-47760: TinyMCE 6.8.x through 7.0.x mishandled SVG namespace scope while sanitizing nested `<svg>` markup. A crafted rich-text payload could preserve executable JavaScript attributes that should have been stripped.
- **skillctl skill-library path traversal and symlink-follow** — [GHSA-wx3m-whqv-xv47](https://github.com/advisories/GHSA-wx3m-whqv-xv47): `skillctl` before 0.1.2 allowed malicious skill libraries or `.skills.toml` files to cross project/library path boundaries. Reported primitives included symlink round-trip file disclosure during copy/push, arbitrary writable-directory deletion through absolute or `..` paths in `destination` / `source_path`, `detect --target` traversal, and fork names of `.` / `..` resolving outside the intended root.
- **Admidio PKCS#12 private-key export CSRF** — [GHSA-4rgq-38mh-9xqg](https://github.com/advisories/GHSA-4rgq-38mh-9xqg) / CVE-2026-47232: Admidio through 5.0.9 had a commented-out CSRF validation call in `modules/sso/keys.php?mode=export`, allowing a cross-site POST from an authenticated administrator browser to trigger PKCS#12 export with an attacker-chosen export password.

## Operator triage

1. Search for applications embedding TinyMCE 6.8.x-7.0.x, especially CMS/admin editors, helpdesk macros, page builders, email-template editors, and Markdown/HTML import paths that later render saved content to other users.
2. Prioritize TinyMCE deployments where stored rich text crosses privilege boundaries: author to admin, tenant user to support agent, customer profile to back-office, template editor to email recipients, or comment/import content to moderators.
3. Search developer workstations, CI jobs, and agent-skill repositories for `skillctl<0.1.2`, committed `.skills.toml`, custom skill-library mirrors, and automated `skillctl pull`, `push`, or `detect` runs against pull-request-controlled content.
4. Treat skill-library content as executable-adjacent supply chain material: a malicious PR that changes only metadata or symlink layout can become a local file disclosure/deletion path when a maintainer runs the tool.
5. Search Admidio deployments using SSO keys and admin-accessible `modules/sso/keys.php`. Prioritize installations where an attacker can make an administrator browse attacker-controlled HTML while logged in.

## Replayable validation boundaries

### TinyMCE nested-SVG sanitizer canary

Keep proofs inert until you confirm the vulnerable sanitizer branch. Do not deliver payloads to real users.

1. In a disposable instance or an in-scope staging editor, confirm the exact TinyMCE package and asset version. Check npm/composer/nuget dependency metadata and the browser-loaded `tinymce.min.js` path/hash.
2. Submit a harmless baseline SVG fragment through the same editor/import endpoint and save it. Record what the sanitizer strips or preserves.
3. Submit a nested-namespace SVG canary with a non-executing marker attribute and a visibly unique text marker. If active JavaScript proof is allowed, use only a same-page benign marker such as setting a test-only DOM attribute; avoid credential, cookie, or network exfiltration payloads.
4. Vulnerable result: the saved/rendered HTML preserves an executable event or URL attribute inside nested SVG where the sanitizer should have removed it, and the marker executes or remains reachable when rendered from stored content.
5. Capture version, editor configuration, input markup class, sanitized output, render context, required role, and audience that can view the stored content. Redact any real user content.

### skillctl path-safety and symlink canaries

Run only in a scratch workspace with fake marker files. Do not point tests at home directories, SSH material, cloud credentials, production repos, or shared skill libraries.

1. Create a disposable project root, disposable skill-library root, and a fake secret file under a temp directory.
2. Build a malicious test skill folder containing a symlink to the fake secret. Exercise the same copy/push path the target workflow uses.
3. Vulnerable result for disclosure: the destination project/library contains the symlink target's file bytes, not a rejected symlink or inert link placeholder.
4. Build a `.skills.toml` canary with `destination` or `source_path` set to an absolute path or `..` traversal that resolves to a harmless marker directory outside the project.
5. Vulnerable result for deletion/write-boundary issues: `pull`, `push`, or `detect` attempts to remove, replace, or write outside the expected project/library root.
6. Test `detect --target` and fork-name handling only against scratch paths. Vulnerable result: `..`, `.`, or absolute-equivalent path components escape the intended root.
7. Capture the exact `skillctl` version, command, sanitized config snippet, resolved path, before/after tree, and rejected/accepted symlink behavior. Report this as a **skill-library ingestion boundary failure**, not as generic local file access.

### Admidio key-export CSRF proof

This is a sensitive export action. Use a lab administrator and a throwaway SSO keypair only.

1. Stand up Admidio 5.0.9 or earlier with a disposable SSO keypair and a lab administrator session.
2. Baseline the legitimate export form and record whether a CSRF token is normally present.
3. From a separate attacker-controlled origin, submit a POST to `/modules/sso/keys.php?mode=export&uuid=<lab-key-uuid>` with `key_password=<lab-password>` and no CSRF token.
4. Vulnerable result: the browser receives an `application/x-pkcs12` response or file download even though no valid anti-CSRF token was supplied.
5. Because same-origin policy usually prevents directly reading the cross-site response, frame impact around forced sensitive action, administrator browser download behavior, and any same-origin or user-assisted path in scope. Do not claim direct key exfiltration unless the target context actually exposes the response to the attacker.
6. Capture role, endpoint, token omission, response content type/disposition, and successful parsing of the lab `.p12` with OpenSSL. Do not include private key material in reports.

## Reporting heuristics

- Frame TinyMCE findings as **stored rich-text sanitizer namespace confusion**. Strong reports include sanitized-output diffs and the privilege boundary crossed by saved content.
- Frame skillctl findings as **untrusted skill metadata/filesystem layout escaping the project/library root**. Show a fake marker file crossing a boundary or a scratch directory being targeted; never demonstrate against real secrets.
- Frame Admidio findings as **CSRF on private-key export**, with careful language about browser-triggered export versus attacker-readable response.

## Sources

- GitHub Advisory Database: [GHSA-mh5m-5hw4-5c69 / CVE-2026-47760](https://github.com/advisories/GHSA-mh5m-5hw4-5c69)
- TinyMCE advisory/source: <https://github.com/tinymce/tinymce/security/advisories/GHSA-mh5m-5hw4-5c69> and <https://github.com/tinymce/tinymce>
- GitHub Advisory Database: [GHSA-wx3m-whqv-xv47](https://github.com/advisories/GHSA-wx3m-whqv-xv47)
- skillctl advisory/source: <https://github.com/umanio-agency/skillctl/security/advisories/GHSA-wx3m-whqv-xv47> and <https://github.com/umanio-agency/skillctl>
- GitHub Advisory Database: [GHSA-4rgq-38mh-9xqg / CVE-2026-47232](https://github.com/advisories/GHSA-4rgq-38mh-9xqg)
- Admidio advisory/source: <https://github.com/Admidio/admidio/security/advisories/GHSA-4rgq-38mh-9xqg> and <https://github.com/Admidio/admidio>
