# elFinder ImageMagick CLI command injection

Source: GitHub Security Advisory [GHSA-8q4h-8crm-5cvc](https://github.com/advisories/GHSA-8q4h-8crm-5cvc) / CVE-2026-41247, updated 2026-05-06.

This is durable because file-manager image operations often look like harmless media metadata handling while still crossing into shell-backed processing. Any user-controlled image option that reaches a CLI command line is an execution boundary.

## Advisory summary

- **Product/package:** `studio-42/elfinder` / elFinder.
- **Impact:** command injection in the `resize` command when the ImageMagick CLI backend is used.
- **Trigger:** attacker-controlled `bg` / background-color parameter reaches resize or rotate processing and is interpolated into shell command construction.
- **Affected versions:** before 2.1.67.
- **Patched version:** 2.1.67.
- **Severity:** high; GitHub reports CVSS 3.1 score 9.8.

## Operator triage

1. Upgrade elFinder to **2.1.67 or later**.
2. If immediate upgrade is blocked, disable the `resize` command or avoid the ImageMagick CLI backend until fixed.
3. Restrict file-manager access to trusted users only; do not expose image-processing actions anonymously or broadly to low-privilege accounts.
4. Search web logs for `resize` requests containing unusual `bg` values, shell metacharacters, command separators, substitutions, encoded payloads, or unexpected color formats.
5. Check web-server process logs, ImageMagick temporary directories, and child-process telemetry for unexpected command execution around image resize activity.
6. Treat successful exploitation as code execution as the web-server user: preserve evidence, rotate secrets accessible to that user, and rebuild compromised hosts from clean images.

## Durable controls

- Prefer library APIs or argv-array process execution over shell string construction for media tools.
- Validate media options against strict grammar allowlists before they reach any backend. For colors, accept only explicitly supported forms such as named colors or bounded hex/RGB forms.
- Escape is a backup, not the boundary. The primary boundary is rejecting values that are not valid for the intended semantic field.
- Run image processing in a sandboxed worker with low privileges, no cloud metadata access, tight filesystem scope, and CPU/memory/time limits.
- Log normalized image-operation parameters and backend selection so suspicious transformations can be hunted after disclosure.
