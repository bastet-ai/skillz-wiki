# 2026-02-03 — `@isaacs/brace-expansion` unbounded expansion → DoS (GHSA-7h2j-956f-4vf2)

**Summary:** `@isaacs/brace-expansion` can perform **eager, unbounded brace-range expansion**. If untrusted input is passed into expansion (directly or via globbing), an attacker can trigger **exponential work** and crash or stall a Node.js process.

- **Component:** `@isaacs/brace-expansion` (npm)
- **Impact:** Denial of service (CPU + memory exhaustion)
- **Exploitability:** depends on whether your app expands **attacker-controlled patterns**

## Why this matters (durable lesson)
This is the broader class of **“algorithmic complexity / input expansion”** bugs:
- Globbing, brace expansion, regex, parsers, and template engines can hide *exponential* behavior behind tiny inputs.
- The failure mode is often *not* a single hot loop, but an explosive intermediate structure (arrays/strings) built before control returns.

## Defensive actions
1. **Never expand attacker-controlled patterns without limits**
   - If your app accepts patterns (globs, brace ranges, regex), treat them as a separate input type with **strict policy**.
   - Prefer **allowlisted patterns** (e.g., `*.jpg` only) over free-form expressions.

2. **Apply complexity limits**
   - Put an upper bound on:
     - maximum range size (e.g., `{0..9999}`)
     - maximum number of expansions
     - maximum output length
   - Fail closed with a clear error.

3. **Contain the blast radius**
   - Add request timeouts.
   - Add per-route rate limits.
   - Use worker isolation if expansion must happen (separate process / queue).

4. **Patch / pin**
   - Update to **5.0.1** (per advisory) or later.

See also: [Secure logging: don’t leak secrets](../best-practices/secure-logging-secrets.md) (different class, same principle: guardrails around “convenience” primitives).

## References
- GitHub Advisory: https://github.com/advisories/GHSA-7h2j-956f-4vf2
