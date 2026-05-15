# AVideo auth, SSRF, command, and transport-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15.

This batch is durable because it repeats a pattern that keeps showing up in media platforms, healthcare client libraries, and developer tooling: endpoints that look like plugin glue or installer convenience code still cross hard security boundaries. Treat stream ingest URLs, Meet upload filenames, shared plugin secrets, 2FA toggles, TLS/signature verification, and archive extraction as attacker-controlled boundary inputs.

## Advisories covered

- **AVideo incomplete SSRF fix** — [GHSA-c3ch-22rq-xfwr](https://github.com/advisories/GHSA-c3ch-22rq-xfwr): `WWBN/AVideo <= 29.0` still has multiple `isSSRFSafeURL()` call sites that discard the resolved-IP out-parameter after the CVE-2026-43884 fix, leaving redirect/DNS/IP-canonicalization bypass risk.
- **AVideo 2FA-toggle CSRF** — [GHSA-3mv2-vmwh-rwfx](https://github.com/advisories/GHSA-3mv2-vmwh-rwfx): `WWBN/AVideo <= 29.0` lets an attacker page silently disable 2FA for a logged-in victim because the 2FA toggle endpoint lacks CSRF protection.
- **AVideo stored XSS in live mode** — [GHSA-m5j4-7r85-2cj2](https://github.com/advisories/GHSA-m5j4-7r85-2cj2): `WWBN/AVideo <= 29.0` reflects an unescaped stream key into a `modeYoutubeLive.php` class attribute, creating stored/scriptable render risk.
- **AVideo `on_publish.php` command injection** — [GHSA-xw67-cg5f-4m2r](https://github.com/advisories/GHSA-xw67-cg5f-4m2r): `WWBN/AVideo <= 29.0` passes an unescaped m3u8 URL into `execAsync()` from the live publish path, allowing OS command injection.
- **AVideo Meet plugin passwordless user impersonation** — [GHSA-qxvm-r42f-5p8j](https://github.com/advisories/GHSA-qxvm-r42f-5p8j): `WWBN/AVideo <= 29.0` derives `users_id` from the uploaded recording filename and calls passwordless `User->login()` for callers with the Meet shared secret, enabling arbitrary user sessions including admin.
- **epa4all-client signature verification bypass** — [GHSA-gqx7-6552-67hf](https://github.com/advisories/GHSA-gqx7-6552-67hf): `com.oviva.telematik:epa4all-client` improperly verifies cryptographic signatures, weakening trust in signed protocol messages.
- **epa4all-client production TLS validation disabled** — [GHSA-5hhf-xmfx-4vvr](https://github.com/advisories/GHSA-5hhf-xmfx-4vvr): `com.oviva.telematik:epa4all-client` disables TLS certificate validation in production paths, exposing traffic to interception or modification.
- **Microsoft APM archive path overwrite** — [GHSA-mq5j-pw29-jcv3](https://github.com/advisories/GHSA-mq5j-pw29-jcv3): Microsoft APM legacy-bundle probing during `apm install` can overwrite Windows absolute paths from malicious tar members.

## Operator triage

1. Treat exposed AVideo `<= 29.0` as high priority when live streaming, Meet recordings, remote URL fetches, or 2FA account-management routes are enabled. Disable nonessential Meet/live/plugin endpoints until patched or wrapped with compensating controls.
2. Source-restrict live ingest callbacks and Meet upload endpoints. Review web, RTMP, process, and shell logs for suspicious m3u8 values, metacharacters, unexpected Meet shared-secret use, recording filenames that encode user IDs, and admin sessions created near recording uploads.
3. Re-check all AVideo SSRF call sites, not just the central helper. The caller must consume the canonical/resolved destination that was validated; validation results that are discarded are not a control.
4. Rotate AVideo admin sessions, Meet/plugin shared secrets, stream keys, and any credentials reachable from internal URLs if command injection, SSRF, or impersonation indicators are present.
5. For `epa4all-client`, upgrade when a fixed release is available and pin compensating controls now: enforce platform TLS validation, certificate/hostname checks, and strict signature validation before processing signed healthcare protocol messages.
6. For Microsoft APM, avoid installing untrusted legacy bundles and run installer workflows in disposable, least-privileged sandboxes. Inspect tar members for absolute paths, drive-letter paths, UNC paths, `..`, symlinks, and hardlinks before extraction.

## Durable controls

- SSRF validation must return a canonical destination object and require callers to use it. A helper that validates one URL/IP but lets the caller connect to another value is bypassable by design.
- State-changing account controls, especially 2FA disablement, require CSRF tokens or strict origin/Fetch Metadata checks plus fresh-user verification.
- Never build shell commands from stream, webhook, or media URLs. Use argv arrays, no shell interpolation, URL allowlists, and privilege-separated workers.
- Plugin shared secrets are not user identity. Treat them as endpoint authentication only; object ownership and target user IDs must come from server-side authorization decisions.
- Render stream keys, filenames, and upload metadata with context-specific encoders before they reach HTML attributes, JavaScript, logs, or admin dashboards.
- TLS and signature verification should fail closed in production. Test negative cases: wrong hostnames, unknown CAs, altered signatures, missing signatures, and replayed protocol messages.
- Archive extraction must be containment-first: reject absolute paths, parent traversal, symlinks/hardlinks that escape the destination, device paths, and platform-specific path aliases before writing files.
