# OctoPrint upload reserved-field file-boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entry: GitHub Advisory Database [GHSA-j4h9-pm27-4rfw](https://github.com/advisories/GHSA-j4h9-pm27-4rfw) / CVE-2026-54134.

This is durable for operators because it exposes a reusable upload-pipeline boundary: a fronting upload handler streams files to temporary disk locations, then injects internal form fields for the Flask application. If a user with `FILE_UPLOAD` can control those reserved fields or related query parameters, host-readable files can be moved into OctoPrint's upload area and downloaded as if they were normal uploads.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j4h9-pm27-4rfw](https://github.com/advisories/GHSA-j4h9-pm27-4rfw) / CVE-2026-54134 | OctoPrint upload endpoints | request-supplied upload metadata crossed into server-side temp-file handling and file moves | Test custom upload handlers for reserved parameter spoofing, path canonicalization, and whether low-privileged upload roles can relocate canary files into downloadable storage. |

Adjacent [GHSA-p6qx-ghxm-389h](https://github.com/advisories/GHSA-p6qx-ghxm-389h) was processed without a standalone page because suppressed-command notification XSS is useful only in narrower printer-admin UI scopes. Revisit it if paired with a stronger workflow around low-privileged printer users reaching privileged admin browser state with inert UI markers.

## Operator triage

1. **Confirm role and feature reachability.** The high-value precondition is a scoped user with `FILE_UPLOAD`; do not describe this as unauthenticated host file read.
2. **Map the upload pipeline.** Identify whether requests pass through Tornado's streaming upload handler before Flask and which form/query fields are reserved for internal handoff.
3. **Use synthetic files only.** Create a canary file in a lab path readable by the OctoPrint process. Do not target `config.yaml`, API keys, G-code from real users, serial logs, SSH keys, cloud credentials, or OS files.
4. **Prove relocation, not data theft.** A before/after path table and successful download of the synthetic marker is enough.
5. **Record fixed-version controls.** Pair the vulnerable behavior with OctoPrint 1.11.8 or 2.0.0rc3 rejection where possible.

## September 22 follow-up: same product, adjacent API legs (public exploits)

- **OctoPrint Command API `executeSystemCommand` OS-command injection** ([GHSA-jwf4-wmgv-pvqx](https://github.com/advisories/GHSA-jwf4-wmgv-pvqx) / CVE-2026-94490, `src/octoprint/server/api/system.py`): the `command` argument crosses into a shell. This is the OctoPrint instance of the standing rule that **any "run a configured command" API is an argv-injection sink until a flag allowlist is proven** (Aug 5 command-wrapper page); treat a low-sev rating as scope-limited (authenticated caller), then check what else reaches the same helper. Exploit is public.
- **OctoPrint File Download API `_validate` filename path traversal** ([GHSA-6wqw-4v48-3xjc](https://github.com/advisories/GHSA-6wqw-4v48-3xjc) / CVE-2026-94489, `src/octoprint/server/api/files.py`): download-route filename reaches the filesystem unconfined — same lexical-containment class as the June 23 reserved-field item on this page. Exploit is public.
- Operator value: the vendor was contacted and did not respond, and exploits are public — on authorized targets, fingerprint OctoPrint builds, then test both legs against your own canary path/marker command only. These pair with the upload-handler leg above into a three-leg picture: upload handoff fields, download filename, and system-command API are the three places this product's file/exec boundaries were each independently broken.

## Replayable validation boundary

- Preconditions: owned OctoPrint lab or explicit bug-bounty scope, disposable `FILE_UPLOAD` user, test upload folder, and one synthetic canary file readable by the OctoPrint service account.
- Send a baseline upload of an inert `.gcode` or text marker and capture the expected server-generated temporary-file handoff behavior.
- Send paired requests that attempt to supply or override reserved upload-handler fields or query parameters with the synthetic canary path. Keep request bodies small and reversible.
- Positive evidence is limited to the canary being moved or exposed through the normal upload-download route. Stop before reading real application configuration or deleting runtime files.
- Negative controls: reserved fields stripped from client input, temp-file identifiers bound to server-created upload sessions, canonical source paths confined to the upload temp directory, and patched versions rejecting spoofed handoff metadata.

## Reporting notes

- Lead with the boundary: **`FILE_UPLOAD` user-controlled handoff fields to OctoPrint host-file move/download**.
- Include OctoPrint version, role permissions, route names, sanitized parameter names, canary path, upload folder path, and patched rejection behavior.
- Keep evidence non-sensitive: synthetic marker contents, directory listings of disposable folders, redacted request/response pairs, and route/status matrices.
- Do not publish payloads that read secrets or remove important runtime files; the useful report is the upload-handler trust break.
