# AVideo platform trust-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it shows how self-hosted media/community platforms fail when user-controlled content crosses into trusted platform channels: profile assets, subscriber email, OAuth redirect state, realtime socket relays, and clone/replication endpoints.

## Advisories covered

- **AVideo `userSavePhoto.php`** — [GHSA-jw8g-5j46-44rp](https://github.com/advisories/GHSA-jw8g-5j46-44rp): CSRF could overwrite an authenticated user profile photo with attacker-chosen content.
- **AVideo `notifySubscribers.json.php`** — [GHSA-g9cm-rxp7-6gv5](https://github.com/advisories/GHSA-g9cm-rxp7-6gv5): HTML injection allowed platform-branded phishing emails to channel subscribers.
- **AVideo MobileManager OAuth redirect** — [GHSA-5w8w-26ch-v5cw](https://github.com/advisories/GHSA-5w8w-26ch-v5cw): password hash exposure in redirect URL could enable account takeover.
- **AVideo YPTSocket `autoEvalCodeOnHTML` bypass** — [GHSA-ghcv-22jf-vfxm](https://github.com/advisories/GHSA-ghcv-22jf-vfxm): incomplete filtering let unauthenticated input trigger cross-user JavaScript execution through `$msg['json']` relay handling.
- **AVideo `cloneClient.json.php`** — [GHSA-qm9p-p5pw-jrx2](https://github.com/advisories/GHSA-qm9p-p5pw-jrx2): error echo disclosed CloneSite `myKey`, enabling cross-site database dump of the configured clone server.

## Operator triage

1. Treat internet-facing AVideo instances as high priority if subscriber email, clone/sync, OAuth/mobile, or socket features are enabled.
2. Disable clone-client and realtime relay features until patched or protected behind explicit admin-only access controls.
3. Rotate CloneSite keys, OAuth secrets, API keys, and user/session credentials if suspicious redirect, clone, or socket traffic is present.
4. Hunt web logs for `cloneClient.json.php`, `notifySubscribers.json.php`, `userSavePhoto.php`, MobileManager OAuth redirects containing hash-like values, and socket messages carrying nested JSON/HTML/script payloads.
5. Review outbound subscriber emails for injected HTML, lookalike login links, credential prompts, and platform-branded phishing content.

## Durable controls

- CSRF protection must cover media/profile mutations, not only high-value admin actions.
- Platform-branded email should render from templates with escaped user fields; raw HTML from channel owners or request parameters should never enter bulk mail.
- OAuth redirects and deep links must not carry password hashes, API keys, clone secrets, or reusable bearer material.
- Realtime socket relays need schema validation and inert rendering by default; never run relay payloads through `eval`-like HTML/JS execution helpers.
- Clone/replication endpoints should fail closed with redacted errors, per-peer scoped secrets, and audit events on every sync/export attempt.
