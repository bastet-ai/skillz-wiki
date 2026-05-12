# OpenClaude MCP OAuth callback state boundary

**Signal:** GitHub Security Advisories REST fallback surfaced [GHSA-c73c-x77g-854r](https://github.com/advisories/GHSA-c73c-x77g-854r) / CVE-2026-42073 for `@gitlawb/openclaude < 0.5.1`: the temporary local MCP OAuth callback server skipped `state` validation whenever the callback included an `error` parameter, allowing a cross-origin request to shut down the user's active auth flow.

## Why this matters

Local OAuth callbacks are still web attack surfaces. A loopback listener that trusts “this only runs during login” can be hit by a malicious browser tab, local page, or adjacent process while the user is authorizing an MCP/agent integration. If error handling runs before `state` validation, attackers can convert an OAuth CSRF defense into a denial-of-service primitive and, in similar flows, sometimes into token/session confusion.

## Triage

1. Upgrade `@gitlawb/openclaude` to **0.5.1+**.
2. Treat any failed or interrupted OpenClaude MCP authorization attempts on affected versions as potentially attacker-triggered; retry only after patching.
3. Review local callback handlers for conditional patterns like `if (!error && state !== expectedState)` or any code path where `error`, `code`, `redirect`, or provider-specific parameters are processed before `state`.
4. Confirm callback listeners bind to loopback only, use single-use high-entropy state values, expire quickly, and shut down only after validated terminal states.
5. Add regression tests that send callbacks with mismatched/missing `state` plus `error`, duplicate parameters, encoded keys, unexpected methods, and wrong paths.

## Durable controls

- Validate `state` first for every callback request, independent of whether the provider returns `code`, `error`, or malformed parameters.
- Make cleanup paths state-aware: an unauthenticated request should not be able to terminate another in-progress login session.
- Keep OAuth callback servers minimal: strict path, method, host binding, timeout, one-shot state, and no wildcard CORS assumptions.
- Log rejected callback attempts with remote address, path, parameter shape, and reason, without recording authorization codes or tokens.
- For MCP/agent tools, separate identity setup from privileged tool execution; a failed auth flow should leave no reusable partial session or cached credential.
