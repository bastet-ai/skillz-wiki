# Form merge prototype-pollution boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11.

This batch is durable because it shows prototype pollution moving through routine server plumbing: a generic deep merge helper and a form-data path setter. Both are easy to dismiss as library bugs, but both can turn ordinary HTTP input into process-wide mutation in Node.js applications.

## Advisories covered

- **`@theecryptochad/merge-guard` `deepMerge()` prototype pollution** — [GHSA-mhwj-73qx-jqxm](https://github.com/advisories/GHSA-mhwj-73qx-jqxm): npm `@theecryptochad/merge-guard <1.0.1` recursively merged source objects without blocking `__proto__`, `constructor`, or `prototype`, allowing attacker-controlled source objects to mutate `Object.prototype`. Fixed in `1.0.1`.
- **`@rvf/set-get` form-data path prototype pollution** — [GHSA-c567-44rc-m5hq](https://github.com/advisories/GHSA-c567-44rc-m5hq): npm `@rvf/set-get >=6.0.0,<6.0.4` and `>=7.0.0,<7.0.2`, reachable through `@rvf/core` form helpers such as `preprocessFormData`, `parseFormData`, and `validate`, accepted field names that walked into `__proto__`, `constructor`, or `prototype`. Fixed in `6.0.4` and `7.0.2`.

## Operator triage

1. Patch `@theecryptochad/merge-guard` to **1.0.1+** and `@rvf/set-get` to **6.0.4+** or **7.0.2+**. Also refresh `@rvf/core` lockfiles so the patched transitive package is actually installed.
2. Search request logs and form submissions for field names containing `__proto__`, `constructor`, `prototype`, bracket notation, dotted paths, or encoded variants.
3. Add runtime canaries in high-risk Node services: after request parsing and config merging, assert `({}).polluted === undefined` and similar sentinel properties remain unset.
4. Review downstream sinks that read inherited properties after parsing forms or merging config: auth flags, template options, HTTP client options, file paths, and command execution settings.
5. If exploitation is plausible, restart affected Node processes after patching; polluted prototypes persist for the life of the process.

## Durable controls

- Treat path setters and deep merge utilities as security-sensitive parsers, not convenience code.
- Reject prototype-reserved keys before every nested assignment, including dotted, bracketed, URL-encoded, Unicode-normalized, and array-indexed forms.
- Merge untrusted input into null-prototype dictionaries or `Map`, then project only validated fields into application objects.
- Keep prototype-pollution tests in framework-level form helpers, not only in application-specific routes.
- Investigate prototype pollution as a source-and-sink problem: patch the write primitive, then hunt for inherited-property reads that could turn pollution into auth bypass, SSRF, XSS, or RCE.
