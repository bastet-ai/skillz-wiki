# 2026-02-05 — NiceGUI `FileUpload.name` path traversal → arbitrary file write (GHSA-9ffm-fxg3-xrhh)

GitHub published an advisory describing a **path traversal / arbitrary file write footgun** in NiceGUI applications that save uploads using a **user-controlled filename**.

- Advisory: <https://github.com/advisories/GHSA-9ffm-fxg3-xrhh>

## Why this matters (durable guidance)

This pattern shows up far beyond NiceGUI:

- you accept an upload
- you do `UPLOAD_DIR / file.name`
- attacker supplies `../.../app.py` (or similar)

Result: writes **outside** the intended directory, which can become **RCE** if a writable file is executed/loaded later.

## Affected

- Apps using NiceGUI `ui.upload()` where server code uses `e.file.name` (or any client-provided filename) in the filesystem path.

## Triage

1. Grep for patterns like:
   - `e.file.name`
   - `UPLOAD_DIR / ...name...`
   - `save(` with a path derived from user input
2. Identify what writable paths would be reachable via traversal:
   - app source files
   - configs
   - scheduled jobs / service units

## Mitigation

**Don’t use the client filename as a path.**

- Generate a server-side name (UUID) and store original name as metadata.
- If you must keep the name:
  - strip directory components (`Path(name).name`)
  - restrict to an allowlist character set
  - enforce a base directory check using `resolve()` and `is_relative_to()`.

See also: [Best practice: file uploads — don’t trust filenames](../best-practices/file-upload-filename-sanitization.md)

## Hunt / detection ideas

- Monitor for upload requests with suspicious filenames:
  - `../`, `..\\`, `%2e%2e%2f`, mixed slashes
- Alert on writes outside your upload directory (auditd / EDR file events).

## References

- <https://github.com/advisories/GHSA-9ffm-fxg3-xrhh>
- NiceGUI source references are linked from the advisory.
