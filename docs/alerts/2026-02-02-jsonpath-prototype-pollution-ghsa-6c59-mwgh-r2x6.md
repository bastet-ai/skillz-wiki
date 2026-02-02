# 2026-02-02 — `jsonpath` (NPM) prototype pollution (CVE-2025-61140 / GHSA-6c59-mwgh-r2x6)

## Summary

GitHub reviewed an advisory for **prototype pollution** in the NPM package **`jsonpath`**.

- Advisory: https://github.com/advisories/GHSA-6c59-mwgh-r2x6
- CVE: **CVE-2025-61140**
- Affected: **`jsonpath` <= 1.1.1**
- Root cause (per advisory): insufficient input validation of object keys in `lib/index.js` (`value` function)

## Why this matters

Prototype pollution is often “just” data integrity at first, but it can become a **security boundary break** when polluted properties influence:

- authorization decisions (`if (obj.admin) ...`)
- configuration objects (feature flags, template options, request options)
- templating, deep-merge utilities, or code paths that assume trusted object shapes

If untrusted input can reach JSONPath expressions/operations in your app, treat this as **potentially attacker-controlled object mutation**.

## What to do (durable guidance)

1. **Inventory exposure**
   - Search for `jsonpath` in `package.json` and lockfiles.
   - Identify call sites where JSONPath queries are built from **user input**.

2. **Upgrade / replace**
   - The advisory lists **no patched version** at time of writing.
   - Prefer replacing with a maintained JSONPath implementation, or constrain usage to trusted inputs only.

3. **Mitigate prototype pollution at boundaries**
   - Reject or sanitize keys like `__proto__`, `prototype`, `constructor` when mapping user-controlled data into objects.
   - Consider using `Object.create(null)` for “map/dictionary” objects that ingest untrusted keys.
   - Avoid unsafe deep-merge patterns with untrusted input.

4. **Add regression tests**
   - Add a test that attempts to pollute `({}).polluted` (or similar) and asserts it remains `undefined`.

## Related Wisdom

- [Prototype pollution](../best-practices/prototype-pollution.md)
