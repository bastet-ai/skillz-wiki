# 2026-02-07 — Langroid TableChatAgent WAF bypass → RCE in `pandas_eval` (GHSA-x34r-63hx-w57f)

GitHub advisory: <https://github.com/advisories/GHSA-x34r-63hx-w57f>

## Summary

Langroid’s `TableChatAgent` includes a `pandas_eval` capability that evaluates expressions against a DataFrame.

A WAF-like filter added to mitigate an earlier issue can be **bypassed**, enabling attackers who can influence the expression/tool-call arguments to achieve **remote code execution (RCE)**.

This is a classic “agent tool” pitfall:

- a “safe eval” guardrail that can be bypassed
- plus access to Python’s dangerous reflection surface (dunder attributes / `__globals__` / builtins)

## Who is at risk

Higher risk if you:

- Expose `TableChatAgent` (or any `pandas_eval`-style tool) to **untrusted users**.
- Allow the model to call tools with arguments that are **not validated server-side**.
- Run the agent on hosts with:
  - broad filesystem/network access
  - access to secrets (env vars, instance metadata)
  - CI/CD tokens or cloud credentials

## Mitigation

1. **Upgrade**
   - Upgrade `langroid` to **0.59.32** or later (per advisory).

2. **Prefer removing “eval of user input” entirely**
   - Disable `pandas_eval` (or equivalent) if you don’t explicitly need it.
   - Replace with a constrained query interface (e.g., specific analytics operations) instead of free-form expressions.

3. **Hard sandbox the execution** (defense-in-depth)
   - Run the evaluation in a separate, heavily sandboxed process/container with:
     - no secrets mounted
     - tight egress controls
     - read-only filesystem (or tightly scoped writable dir)
     - low privileges (no Docker socket, no host mounts)

4. **Central argument validation for tool calls**
   - Treat tool-call inputs as attacker-controlled:
     - reject dunder access patterns (`__*__`)
     - block attribute traversal / globals / builtins access
     - apply tight allowlists for permitted operations

## Detection / hunt

- Audit logs for suspicious tool-call arguments targeting DataFrame expression evaluation.
- Look for attempted access patterns like:
  - `__init__`, `__globals__`, `__builtins__`, `eval`, `exec`, `import`
- Endpoint telemetry:
  - new outbound connections from the agent host
  - unexpected process spawns (shell, curl/wget)
  - access to environment variables / credential files
