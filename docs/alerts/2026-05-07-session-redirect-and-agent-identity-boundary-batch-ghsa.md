# Session, redirect, and agent identity boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** batch where web sessions, API redirects, agent runs, and local system commands crossed identity boundaries.

## Advisories covered

- **katalyst-koi replayable session cookies after logout** — [GHSA-4cx3-3c38-j9vv](https://github.com/advisories/GHSA-4cx3-3c38-j9vv): logout must invalidate server-side session material, not only remove client-side cookies.
- **Aegra cross-user run injection IDOR** — [GHSA-m98r-6667-4wq7](https://github.com/advisories/GHSA-m98r-6667-4wq7): agent/thread run creation must bind requested thread IDs to the authenticated principal.
- **Kiota RedirectHandler cross-host header leakage** — [GHSA-7j59-v9qr-6fq9](https://github.com/advisories/GHSA-7j59-v9qr-6fq9): redirects can exfiltrate Cookie or Proxy-Authorization headers unless credentials are origin-scoped.
- **container pf rule injection through localhost DNS command arguments** — [GHSA-39g5-644c-qwcg](https://github.com/advisories/GHSA-39g5-644c-qwcg): local admin CLIs still need command-argument validation before emitting firewall rules.

## Why this is durable

Identity can leak at boring seams: logout, redirects, nested object IDs, and generated local config. Each seam must re-bind authority to the current subject and destination instead of carrying ambient credentials forward.

## Immediate triage

1. Patch affected session, Kiota, Aegra, and container CLI versions where used.
2. Force session invalidation for high-risk katalyst-koi deployments and review logout/session-store behavior.
3. Hunt Aegra/API logs for `/threads/{thread_id}/runs` requests where the thread owner differs from the authenticated user.
4. Audit HTTP clients for cross-host redirects that preserve Cookie, Authorization, or Proxy-Authorization headers.
5. Review generated pf rules and localhost DNS names for shell, newline, wildcard, or rule-syntax injection.

## Durable controls

- Store session revocation state server-side and verify it on every authenticated request.
- Authorize nested resource IDs by ownership/tenant before creating agent runs or background jobs.
- Strip credentials on cross-origin or cross-host redirects unless an explicit allowlist says otherwise.
- Generate firewall/DNS rules from structured APIs or strongly typed values, never raw user-provided command strings.
