# 2026-02-05 — SandboxJS: sandbox escape via TOCTOU key-coercion (GHSA-7x3h-rm86-3342)

GitHub advisory: <https://github.com/advisories/GHSA-7x3h-rm86-3342>

## Summary

`@nyariv/sandboxjs` is reported vulnerable to a **sandbox escape** due to a mismatch between:

- the key that is validated/sanitized, and
- the key actually used for the subsequent property access.

Because JavaScript allows objects with attacker-controlled coercion (e.g., `toString()`), an attacker can cause the “validated” key and the “used” key to diverge (a TOCTOU-style bug), potentially enabling **code execution outside the intended sandbox**.

## Practical guidance

If you are using SandboxJS to run **untrusted** or **user-supplied** code:

- Treat this as a **breakout/RCE risk**.
- Upgrade to the fixed version (per advisory).
- If you cannot upgrade immediately:
  - disable untrusted code execution,
  - or move execution into a *real* isolation boundary (separate process/container/VM with hard OS controls).

## Detection / hunt

- Look for SandboxJS usage in your codebase and dependency graph (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`).
- If you provide “run code” features: review logs/telemetry for suspicious executions, unexpected child processes, or file/network access originating from the sandbox runner.
