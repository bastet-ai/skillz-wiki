# App auth, session, and message-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because the failures share the same defensive lesson: browser-facing collaboration and admin tools must enforce authorization at the state-changing endpoint, not only in the UI, channel membership, cookie defaults, or preflight/session assumptions.

## Advisories covered

- **Dozzle CSWSH on container exec/attach** — [GHSA-j643-x8pv-8m67 / CVE-2026-44985](https://github.com/advisories/GHSA-j643-x8pv-8m67): `github.com/amir20/dozzle <=10.5.1` accepts WebSocket upgrades for `/exec` and `/attach` from any origin while JWT cookies can be sent, allowing a malicious same-site origin or localhost page to drive an authenticated victim's interactive container shell.
- **Open WebUI channel message update with read permission** — [GHSA-jgj3-r8hr-9pjw / CVE-2026-44571](https://github.com/advisories/GHSA-jgj3-r8hr-9pjw): `open-webui <=0.8.5`, fixed `0.8.6`, lets authenticated users update standard-channel messages when only read access is checked.
- **Open WebUI message IDOR** — [GHSA-jxwr-g6r6-j3fx / CVE-2026-44569](https://github.com/advisories/GHSA-jxwr-g6r6-j3fx): `open-webui <=0.6.18`, fixed `0.6.19`, allows message update/delete APIs to rely on channel access without validating message ownership.
- **Open WebUI path traversal file write/delete** — [GHSA-j3fw-wc48-29g3 / CVE-2026-44565](https://github.com/advisories/GHSA-j3fw-wc48-29g3): `open-webui <=0.6.9`, fixed `0.6.10`, can write uploaded attacker-controlled files outside the intended path before deletion.
- **Open WebUI CORS/session validation issue** — [GHSA-6xcp-7mpr-m7wm](https://github.com/advisories/GHSA-6xcp-7mpr-m7wm): `open-webui <0.3.33`, fixed `0.3.33`, combines permissive browser trust with weak session validation.
- **Budibase readable auth cookies** — [GHSA-4f9j-vr4p-642r / CVE-2026-42239](https://github.com/advisories/GHSA-4f9j-vr4p-642r): `@budibase/backend-core <3.35.10`, fixed `3.35.10`, sets the JWT-bearing `budibase:auth` cookie with `httpOnly: false`, so any XSS becomes account takeover.
- **Saltcorn login open redirect** — [GHSA-f3g8-9xv5-77gv / CVE-2026-42259](https://github.com/advisories/GHSA-f3g8-9xv5-77gv): `@saltcorn/server <1.4.6`, `1.5.0-beta.0-<1.5.6`, and `1.6.0-alpha.0-<1.6.0-beta.5` let backslash-normalized `dest` values redirect victims off-origin after login.

## Operator triage

1. Patch internet-exposed admin, log, AI-chat, and low-code tools first, especially where they can reach containers, filesystems, credentials, or internal networks.
2. Search access logs for cross-origin WebSocket attempts to Dozzle `/exec` or `/attach`, unexpected Open WebUI message edits/deletes, and uploaded paths containing traversal markers or encoded separators.
3. For Open WebUI and Budibase, assume any known XSS or untrusted plugin/content route can become session theft or data tampering until cookie and endpoint fixes are deployed.
4. Review login redirect parameters in Saltcorn and downstream IdP logs for off-origin destinations, backslashes, encoded slashes, and credential-phishing landing pages.
5. Where patching is delayed, put these apps behind an authenticated reverse proxy with strict origin allowlists, disable container exec features if possible, and restrict admin UI access by network.

## Durable controls

- WebSocket endpoints need explicit `Origin` validation and per-action authorization; cookie authentication alone is not a CSRF/CSWSH defense.
- Backend APIs must validate object ownership and operation-specific permissions on every mutation; frontend button visibility is advisory only.
- File upload paths should be normalized once, resolved against an immutable base directory, and rejected if the final path escapes containment before any write occurs.
- Session cookies for privileged web apps should default to `HttpOnly`, `Secure`, and explicit `SameSite`; readable JWT cookies turn ordinary XSS into full account takeover.
- Redirect allowlists must parse URLs the same way browsers do, including backslash normalization, scheme-relative URLs, encoded separators, and control characters.
