# Nginx-UI WebSocket origin boundary bypass

**Source:** GitHub Security Advisory [GHSA-78mf-482w-62qj](https://github.com/advisories/GHSA-78mf-482w-62qj) / CVE-2026-34403, updated 2026-05-07 06:26 UTC.

## Why this matters

Nginx-UI exposed authenticated WebSocket endpoints with `CheckOrigin` accepting every origin while browser-held tokens were available to cookie-authenticated requests. A malicious page visited by a logged-in administrator can therefore open Nginx-UI WebSockets from an attacker origin and inherit the admin session.

This is the same durable boundary lesson as localhost and desktop-tool CSWSH bugs: WebSocket authentication is not enough when browsers automatically attach ambient credentials.

## Advisory summary

| Advisory | Component | Issue | Fixed version |
|---|---|---|---|
| [GHSA-78mf-482w-62qj](https://github.com/advisories/GHSA-78mf-482w-62qj) / CVE-2026-34403 | `github.com/0xJacky/Nginx-UI` | All WebSocket upgraders accept arbitrary `Origin`; cookie-backed admin sessions can be reused by attacker-controlled pages for cross-site WebSocket hijacking. | `1.9.10-0.20260316053337-1a9cd29a3082`; vendor release guidance points to 2.3.5+ |

Affected authenticated WebSocket surfaces include status, analytics, events, nginx logs, cluster nodes, upgrade operations, and the `/api/pty` terminal path. Impact ranges from metrics/log disclosure to system operation triggering and potential interactive terminal access when stronger interactive protections are not enabled.

## Triage now

- Upgrade Nginx-UI to a fixed vendor release; prefer the current maintained fixed line if package metadata and release tags disagree.
- If Nginx-UI was reachable from user browsers, review exposure of WebSocket paths such as `/api/pty`, `/api/nginx_log`, `/api/events`, `/api/analytic/intro`, `/api/upgrade/perform`, and `/api/cluster/nodes/enabled`.
- Rotate administrator sessions and any secrets likely to appear in nginx logs, terminal sessions, cluster-node data, or operational event streams.
- Require OTP/2FA for terminal access and disable browser-exposed PTY paths where not operationally necessary.

## Hunt prompts

- Search access logs for WebSocket upgrade requests with unexpected `Origin` values, especially public web origins not matching the Nginx-UI host.
- Correlate admin browser activity with `101 Switching Protocols` responses to `/api/pty`, `/api/nginx_log`, `/api/events`, and upgrade/cluster endpoints.
- Review nginx reload/restart, binary upgrade, terminal, and cluster-node actions that occurred while an administrator was browsing unrelated sites.
- Look for log-read bursts or analytics/event subscriptions that do not match normal admin UI navigation.

## Durable controls

- Validate `Origin` on every WebSocket upgrade; allow only the exact administrative origins expected for the deployment.
- Avoid ambient browser credentials for privileged WebSockets. Bind sessions to SameSite/secure cookies plus explicit CSRF or per-connection challenge tokens.
- Treat all browser-reachable admin WebSockets as state-changing endpoints unless proven otherwise.
- Put high-impact channels such as PTY, upgrade, restore, and cluster mutation behind a second interaction boundary, not just an already-authenticated browser session.
