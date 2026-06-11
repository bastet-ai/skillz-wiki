# CodeIgniter4 upload extension validation boundary

Source: hourly offensive-security scan, 2026-06-11. Primary entry: GitHub advisory [GHSA-2gr4-ppc7-7mhx](https://github.com/advisories/GHSA-2gr4-ppc7-7mhx) / CVE-2026-48062, with upstream advisory [codeigniter4/CodeIgniter4 GHSA-2gr4-ppc7-7mhx](https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-2gr4-ppc7-7mhx).

This is durable for operators because it turns a common upload-validation assumption into a replayable boundary check: framework validation that appears to restrict a filename extension may actually validate a MIME-derived guessed extension, while the application later preserves the client filename in a web-executable upload path.

## What changed

CodeIgniter4's `ext_in` upload validation rule checked the extension guessed from the file's MIME type rather than the extension in the client-provided filename. An upload such as a file named `shell.php` with GIF-like bytes could satisfy a rule chain like:

```text
uploaded[avatar]|is_image[avatar]|mime_in[avatar,image/gif]|ext_in[avatar,gif]
```

The advisory states that applications are impacted when all of these conditions line up:

- user-controlled file uploads are accepted;
- the application relies on `ext_in` to validate the uploaded filename extension;
- the application saves the upload with the original client filename, for example `$file->move($path)`;
- the destination is web-accessible; and
- the web server executes PHP or another dangerous file type from that destination.

The vulnerable package is `codeigniter4/framework < 4.7.2`; the listed patched version is `4.7.3`.

## Operator triage

1. **Find CodeIgniter4 upload surfaces.** Prioritize profile images, attachments, CMS media, imports, support-ticket files, and admin plugin/theme uploaders.
2. **Confirm the validation chain.** Look for `ext_in[...]`, `mime_in[...]`, `is_image[...]`, and `uploaded[...]` combinations in controllers, request validators, or form-request equivalents.
3. **Check filename preservation.** The important sink is saving with the original client name. `$file->move($path)` without a random safe name is stronger evidence than validation alone.
4. **Map the serving path.** Confirm whether the upload directory is reachable under the web root and whether the server treats `.php`, `.phtml`, or another uploaded extension as executable.
5. **Avoid overclaiming.** Validation bypass is enough for a finding only if the dangerous extension can persist. RCE requires the saved object to be executable through the target's serving stack.

## Replayable validation boundary

Use a lab clone or explicit customer-approved upload canaries. Do not upload a functional shell to production.

1. Prepare a harmless polyglot-style marker file with an executable-looking extension and benign image-like bytes:

    ```bash
    printf 'GIF89a\nSKILLZ-CI-UPLOAD-CANARY\n' > skillz-ci-canary.php
    ```

2. Submit it to the suspected upload field where the application expects `gif` or another image extension.
3. Record whether framework validation accepts the file even though the client filename extension is not in the intended allowlist.
4. If the application preserves the original filename, request only a harmless URL fetch for the uploaded object and capture the server behavior:
    - static download of `skillz-ci-canary.php` proves filename persistence and web reachability;
    - script execution behavior should be tested only in a lab or with a non-executing canary such as a route that prints plain text by design;
    - never deploy a command shell, reverse shell, or credential-reading payload.
5. Compare with a patched or hardened path: randomized stored name, upload directory outside web root, explicit client-extension check, or blocked script execution.

## Evidence to capture

- CodeIgniter4 version and `codeigniter4/framework` package constraint.
- The exact validation rule chain containing `ext_in`.
- The upload request metadata: field name, submitted filename, content type, and benign canary bytes.
- The server-side stored filename or returned media URL.
- Whether the destination is public and whether dangerous extensions execute, download, or are blocked.
- A negative control where a non-image byte sequence fails `mime_in`/`is_image`, showing the bypass is specifically MIME-derived extension acceptance plus filename preservation.

## Report wording

Lead with the crossed boundary:

> The upload workflow validates a MIME-derived extension with CodeIgniter4 `ext_in`, but later stores the client-controlled filename in a public upload path. A file named with a dangerous extension and benign image-like bytes is accepted and persisted under that dangerous extension.

Keep impact conditional. Use **arbitrary file upload / dangerous extension persistence** when execution is not demonstrated. Use **remote code execution** only when the target's approved test environment executes the persisted file as code.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. The Kolibri, Hapi inert, Keycloak, Flowise, and Arc advisories were already promoted in the adjacent 2026-06-11 batch. Newly visible GitHub items that were availability-only, duplicate of existing coverage, or lacked a stronger reusable offensive validation boundary were tracked but not promoted.
