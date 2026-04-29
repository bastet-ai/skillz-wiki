# PhpSpreadsheet HTML writer XSS via custom number format (GHSA-hrmw-qprp-wgmc)

**Signal:** GitHub Security Advisory updated **2026-04-28**. PhpSpreadsheet's HTML writer could skip escaping when a custom number format transformed text with the `@` placeholder.

## What it is
PhpSpreadsheet compared formatted cell output to the original value to decide whether `htmlspecialchars()` was needed. A malicious spreadsheet can set a custom number format such as `. @`, `@ `, or `x@`; the formatter changes the rendered string, the equality check fails, and the HTML writer can emit attacker-controlled cell text without escaping.

Applications are most exposed when they:

1. accept user-uploaded XLSX/spreadsheet files,
2. convert them to HTML with PhpSpreadsheet, and
3. display that HTML to other users or admins.

References:
- GitHub advisory: <https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-hrmw-qprp-wgmc>

## Triage
1. Search for `PhpOffice\\PhpSpreadsheet\\Writer\\Html` usage.
2. Identify upload-to-preview flows, report viewers, admin review queues, and document portals.
3. Check whether generated HTML is sanitized again before rendering.
4. Prioritize multi-tenant or staff-facing views where uploaded spreadsheets are reviewed by privileged users.

## Mitigation
- Upgrade PhpSpreadsheet to a fixed version when available.
- Sanitize generated HTML with a strict allowlist sanitizer before display.
- Render uploaded spreadsheets in a sandboxed iframe with scripts disabled when previews are required.
- Strip or normalize custom number formats before HTML conversion if business logic allows it.
- Serve generated previews from an isolated origin with no ambient application cookies.

## Detection ideas
Look for uploaded spreadsheets with custom number formats containing `@` plus literal characters, especially formats such as:

- `. @`
- `@ `
- `x@`

Correlate with generated preview access by privileged users and any follow-on account changes or suspicious admin actions.

## Durable lesson
File conversion is content rendering. Do not assume library-generated HTML is safe just because the source format is “office data” rather than HTML.
