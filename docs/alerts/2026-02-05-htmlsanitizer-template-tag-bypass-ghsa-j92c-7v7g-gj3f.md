# 2026-02-05 — HtmlSanitizer bypass via `<template>` tag (GHSA-j92c-7v7g-gj3f)

**Product:** .NET **HtmlSanitizer** (NuGet: `HtmlSanitizer`)

## Impact (per advisory)
If the sanitizer configuration allows the **`<template>`** tag, its contents may be **left unsanitized**, enabling XSS.

Risk increases if `shadowrootmode` is allowed, which can cause template content to render.

**Fixed:** **9.0.892** (and **9.1.893-beta**)

## Recommended actions
- **Upgrade** to **9.0.892+** (or 9.1.893-beta+).
- Keep `<template>` **disallowed** unless you have a strong reason.
- Avoid allowing `shadowrootmode` unless you fully understand the implications.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-j92c-7v7g-gj3f>
