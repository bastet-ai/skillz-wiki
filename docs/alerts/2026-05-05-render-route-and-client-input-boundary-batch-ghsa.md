# Render, route, and client-input boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it shows how client-side and SDK trust boundaries fail when untrusted input is routed into privileged renderers, path-building helpers, or desktop IPC surfaces without a strict type/format contract.

## Advisories covered

- **LobeHub / LobeChat `@lobehub/lobehub` <= 2.1.26** — [GHSA-xq4x-622m-q8fq](https://github.com/advisories/GHSA-xq4x-622m-q8fq): stored XSS in artifact/message rendering can chain with insecure Electron IPC exposure to remote code execution. No patched version was listed in the advisory at scan time.
- **@supabase/auth-js <= 2.69.1** — [GHSA-8r88-6cj9-9fh5](https://github.com/advisories/GHSA-8r88-6cj9-9fh5): functions such as `getUserById`, `deleteUser`, `updateUserById`, `listFactors`, and `deleteFactor` accepted malformed `userId`/`factorId` values that could alter the URL path and call an unintended API route. Advisory text lists **2.70.0** as first patched in GitHub metadata and notes strict UUID checks in the patch guidance.

## Operator triage

### LobeHub XSS to Electron RCE

1. Inventory LobeChat/LobeHub deployments, especially desktop/Electron builds and shared workspaces that render attacker-controlled chat, artifact, SVG, Mermaid, Markdown, or custom tag content.
2. If no fixed release is available, disable or tightly restrict artifact/custom HTML rendering for untrusted content. Prefer server-side sanitization plus allowlisted renderers.
3. In Electron, disable Node integration, enforce context isolation, remove dangerous IPC handlers, and require explicit allowlists for every renderer-to-main action.
4. Hunt for messages or artifacts containing custom tags, raw HTML, `<script>`, event-handler attributes, SVG payloads, `javascript:` URLs, or IPC-triggering payload fragments.
5. If a desktop client rendered attacker-controlled payloads, assume main-process command execution may have occurred. Preserve artifacts, collect endpoint telemetry, rotate local/session credentials, and rebuild clients where secrets were exposed.

### auth-js path routing

1. Upgrade `@supabase/auth-js` to a release containing strict UUID checks; prefer **2.70.0+** based on the GitHub advisory metadata.
2. Validate `userId` and `factorId` as UUIDs at your own boundary before passing them into SDK helpers. Do not rely solely on downstream SDK path construction.
3. Search service logs for IDs containing `/`, `%2f`, `..`, `?`, `#`, backslashes, encoded separators, or long path-like strings in calls mapped to user/factor helper functions.
4. Review any administrative tooling that accepts user IDs from support tickets, URLs, CSV imports, browser state, webhooks, or integrations before invoking auth-js management helpers.

## Durable controls

- Renderer dispatch must be allowlist-based. Unknown content types should render as inert text, not raw HTML.
- Treat Markdown, SVG, Mermaid, HTML artifacts, and AI-generated custom tags as active content unless proven otherwise.
- Electron apps need a hard privilege boundary: no Node integration for untrusted renderers, minimal preload APIs, strict IPC schemas, and one IPC handler per explicit capability.
- SDK helper inputs that become URL path segments need type validation before path construction. UUID-looking parameters should be parsed as UUIDs, not concatenated as strings.
- Add path-construction regression tests with encoded separators, dot segments, query fragments, Unicode confusables, and overlong values for every SDK wrapper that calls privileged APIs.
