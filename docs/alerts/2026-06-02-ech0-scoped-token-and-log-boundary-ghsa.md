# Ech0 scoped-token and dashboard-log boundary checks

**Sources:** [GHSA-4h9q-p5j4-xvvh](https://github.com/advisories/GHSA-4h9q-p5j4-xvvh), [GHSA-cp79-9mwr-wr49](https://github.com/advisories/GHSA-cp79-9mwr-wr49)  
**Affected package:** `github.com/lin-snow/ech0` before `4.3.5`  
**Operator value:** delegated-token scope bypass, admin backup export reachability, and low-privilege log-read/stream authorization testing.

## Why this matters

Ech0's June 2026 advisory update adds two authorization-boundary patterns worth reusing during authorized web-app and self-hosted SaaS testing:

- **Scoped admin access tokens can overreach.** Ech0 authenticates access tokens and stores token metadata in context, but privileged routes only enforce least privilege when they explicitly add `RequireScopes(...)`. Several admin surfaces instead rely on `user.IsAdmin`, so a token intentionally scoped to a narrow permission such as `echo:read` can reach broader admin functionality.
- **Backup export drops token metadata.** `/api/backup/export?token=...` reparses a query-string JWT and rebuilds viewer context from only the user ID. That loses token type, audience, scopes, and token ID before the backup service authorizes the request, turning a limited delegated token into a full archive export primitive.
- **Dashboard logs are post-auth but not admin-only.** `GET /api/system/logs`, `GET /api/system/logs/stream?token=...`, and `GET /ws/system/logs?token=...` require a valid JWT but did not require an admin role or privileged scope. A normal user can use those endpoints as a reconnaissance primitive for paths, stack traces, admin activity, internal URLs, background jobs, and other operational context.

This is not just an Ech0-specific bug class. It is a reusable assessment heuristic for any application that offers delegated API tokens, scoped admin tokens, export endpoints, SSE/WebSocket log streams, or query-string token handoff paths.

## Recon targets

Prioritize Ech0 deployments and similar applications that expose:

- self-hosted admin panels with `/api/*` routes and a token-management UI;
- delegated access tokens with user-selectable scopes or audiences;
- backup/export/download endpoints that accept tokens outside the normal authenticated route group;
- dashboard log viewers, live log streams, SSE endpoints, or WebSocket admin telemetry;
- service-layer authorization that checks only `is_admin`, `role == admin`, or account ownership after middleware has already decoded richer token claims.

For Ech0 specifically, start with version identification and route reachability:

```bash
base='https://target.example'

# Confirm the app shape without brute force or invasive crawling.
curl -i "$base/api/system/logs"
curl -i "$base/api/backup/export"
curl -i "$base/api/inbox"
```

Record status codes, redirect behavior, auth challenge format, and any `Server`, app-version, or frontend asset clues. Do not attempt export or log retrieval outside an authorized test account.

## Safe validation workflow

Use a controlled lab or an explicitly authorized tenant with test-only users and disposable tokens.

### 1. Establish control tokens

Create three identities or token types when the target supports them:

- an owner/admin browser session;
- a deliberately low-scope admin access token, for example `echo:read` only;
- a normal non-admin user session token.

Keep token values out of notes, screenshots, logs, and reports. Refer to them as `LOW_SCOPE_ADMIN_TOKEN` and `NON_ADMIN_TOKEN`.

### 2. Check scope enforcement on privileged routes

With the low-scope admin token, probe admin-looking routes that should require broader scope. Capture only response metadata and non-sensitive proof fields.

```bash
base='https://target.example'

curl -sS -o /tmp/inbox.low-scope.json -w '%{http_code}\n' \
  "$base/api/inbox" \
  -H "Authorization: Bearer $LOW_SCOPE_ADMIN_TOKEN"

jq '{code,msg,has_data:(.data != null)}' /tmp/inbox.low-scope.json
```

A finding is strong when all of these are true:

1. the token's configured scope is narrower than the route's administrative purpose;
2. a full-scope or browser-admin session can reach the route as expected;
3. a low-scope admin access token receives the same privileged data or side effect;
4. a non-admin token remains blocked, proving this is a scope boundary failure rather than a public route.

### 3. Check backup/export token metadata loss

Only run this against a test deployment or a target that explicitly permits export validation. Prefer a small canary dataset so archive contents are not sensitive.

```bash
base='https://target.example'

curl -sS -D /tmp/backup.low-scope.headers \
  -o /tmp/backup.low-scope.body \
  "$base/api/backup/export?token=$LOW_SCOPE_ADMIN_TOKEN"

file /tmp/backup.low-scope.body
head -20 /tmp/backup.low-scope.headers
```

Report the boundary issue if a token with insufficient export/admin scope can trigger a ZIP, database, log bundle, or success message. Do not attach the archive. Instead, include redacted evidence such as HTTP status, content type, content length range, and canary filename presence.

### 4. Check dashboard log authorization

Use a normal non-admin test user and request only a small tail if the API supports it.

```bash
base='https://target.example'

curl -sS -o /tmp/logs.nonadmin.json -w '%{http_code}\n' \
  "$base/api/system/logs?tail=5" \
  -H "Authorization: Bearer $NON_A...KEN"

jq '{code,msg,items:(.data|type)}' /tmp/logs.nonadmin.json
```

For streaming endpoints, validate connection authorization without consuming long-running data:

```bash
# SSE: stop after headers/first bytes.
timeout 5 curl -i -N \
  "$base/api/system/logs/stream?token=$NON_ADMIN_TOKEN" \
  -o /tmp/logs.sse.nonadmin.txt

# WebSocket: use a scoped tool in a lab; capture handshake success/failure only.
```

A strong report shows that a non-admin token can read historical logs or establish SSE/WebSocket streams where an admin-only boundary is expected.

## Reporting heuristic

Frame the issue around broken authorization semantics, not just data exposure:

- **Expected boundary:** delegated tokens must be constrained by route scope and audience; low-privilege users must not access operational logs.
- **Observed bypass:** route or handler authenticates the token but skips the scope/admin check, or rebuilds identity from raw JWT claims and drops token metadata.
- **Impact:** limited token becomes broader admin primitive; backup export can expose database/log archive; low-privilege logs can reveal operational context for follow-on attacks.
- **Evidence:** token scope configuration screenshot with token redacted, route/response status matrix, redacted response shape, and canary-only export/log proof.

## Scope and safety notes

- Do not exfiltrate real backup archives or log contents. Use canary deployments or stop after proving archive generation and file type.
- Treat logs as sensitive; redact paths, internal URLs, emails, tokens, stack traces, and usernames before including excerpts.
- Avoid brute-forcing routes. The advisory-confirmed Ech0 surfaces are enough for validation: `/api/inbox`, `/api/backup/export`, `/api/system/logs`, `/api/system/logs/stream`, and `/ws/system/logs`.
- Keep authorization tests within accounts, tenants, and datasets named in the engagement scope.
