# Pheditor, Dex, Phoenix Storybook, and Symfony Runtime boundary checks

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-jvc5-6g7q-c843](https://github.com/advisories/GHSA-jvc5-6g7q-c843) / CVE-2026-48030 for Pheditor, [GHSA-7qjx-gp9h-65qj](https://github.com/advisories/GHSA-7qjx-gp9h-65qj) for Dex, [GHSA-55hg-8qxv-qj4p](https://github.com/advisories/GHSA-55hg-8qxv-qj4p) / CVE-2026-8467, [GHSA-mrhx-6pw9-q5fh](https://github.com/advisories/GHSA-mrhx-6pw9-q5fh) / CVE-2026-47068, and [GHSA-833p-95jq-929q](https://github.com/advisories/GHSA-833p-95jq-929q) / CVE-2026-8469 for Phoenix Storybook, and [GHSA-fqc7-9xjw-jrh3](https://github.com/advisories/GHSA-fqc7-9xjw-jrh3) / CVE-2026-47767 for Symfony Runtime.

This page is durable because the batch highlights four reusable operator patterns: shell allowlists bypassed through an adjacent working-directory parameter, OAuth connector ACLs skipped on token exchange, developer-preview LiveView endpoints exposed as pre-auth code/data boundaries, and web query parsing mismatches that re-enable debug/environment toggles.

## What changed

- **Pheditor terminal handler RCE** — authenticated users with terminal access can bypass the `TERMINAL_COMMANDS` whitelist because shell metacharacter filtering was applied to `command` but not to the `dir` POST parameter before `cd <dir> && <command>` reached `shell_exec()`.
- **Dex token exchange connector ACL gap** — the token-exchange handler validated that the requested connector exists and allows the token-exchange grant, but did not enforce the OAuth client's `allowedConnectors` restriction before issuing Dex-signed tokens.
- **Phoenix Storybook playground RCE** — unauthenticated LiveView clients could send playground attribute values that were interpolated into generated HEEx markup and evaluated with full Elixir `Kernel` access.
- **Phoenix Storybook cross-session iframe topic injection** — the iframe LiveView accepted a PubSub topic from a URL parameter, letting an unauthenticated visitor who knows or guesses another playground topic redirect playground-to-iframe messages to an attacker-controlled process.
- **Phoenix Storybook atom exhaustion is adjacent signal** — unbounded `String.to_atom/1` use on LiveView event params can crash the BEAM VM. Treat it as evidence that unauthenticated playground events reach sensitive server-side conversion paths, not as a standalone availability playbook.
- **Symfony Runtime patch bypass** — the previous `symfony/runtime` guard used `empty($_GET)` as a proxy for CLI context. Crafted web queries can leave `$_GET` empty while `$_SERVER['argv']` still carries flags when `register_argc_argv=On`, restoring unauthenticated `APP_ENV` / `APP_DEBUG` manipulation.

## Operator triage

1. **Inventory exposed developer tooling:** search scoped assets for `pheditor.php`, `/storybook`, `/storybook/iframe/`, Phoenix LiveView WebSocket routes, Symfony front controllers, and Dex `/token` endpoints. Prioritize anything reachable beyond a trusted admin network.
2. **Trace adjacent-parameter shell assembly:** when a feature claims a command allowlist, inspect every parameter that is concatenated into the same shell string: working directory, environment variables, file paths, wrappers, pre/post commands, and logging hooks.
3. **Model OAuth connector policy per grant type:** for Dex or similar brokers, compare authorization-code, connector-login, device, refresh, and token-exchange paths. A policy enforced in the interactive login path may be absent from back-channel exchange.
4. **Identify public Storybook-like surfaces:** Phoenix Storybook belongs in the same recon bucket as Swagger consoles, component playgrounds, preview renderers, and admin debug panels. Look for unauthenticated WebSocket joins and server-side template/render evaluation.
5. **Check Symfony Runtime preconditions:** exploitation requires a web SAPI, `register_argc_argv=On`, boot through `symfony/runtime`, and a vulnerable runtime version. The interesting bug-hunting angle is not the dependency alone; it is whether a crafted query can change observable environment/debug behavior.

## Replayable validation boundaries

### Pheditor command-boundary proof

- Use a lab instance or explicit customer-approved test environment with a disposable authenticated account.
- First show that a disallowed command in `command` is rejected while the same harmless marker routed through `dir` changes command execution behavior.
- Keep validation non-destructive: use `pwd`, `id`, or a synthetic marker file in a temp directory. Do not fetch shells, exfiltrate files, or run persistence payloads.
- Capture the authenticated role, terminal feature state, CSRF handling, sanitized request body, and response showing the allowlist bypass.

### Dex token-exchange ACL proof

- Build a minimal test tenant with two connectors, one restricted client, and a low-value user identity in the connector that should be disallowed for that client.
- Send a token-exchange request specifying the disallowed `connector_id`; a vulnerable deployment issues a token for the restricted client instead of returning a connector-not-allowed error.
- Do not use leaked production client secrets. Use provided test clients or a lab secret and redact tokens in evidence.
- Capture the client `allowedConnectors` configuration, connector grant-type configuration, request grant type, response status, and token claims with signatures or secrets redacted.

### Phoenix Storybook boundary proof

- Confirm whether the storybook route and LiveView WebSocket are reachable without authentication. If authentication is required, stay within the authorized role and scope.
- For HEEx injection, use a harmless expression that returns a synthetic marker from the server process. Avoid OS command payloads unless the customer explicitly approved RCE validation in a disposable environment.
- For PubSub topic injection, use two lab browser sessions and synthetic story state. Demonstrate cross-session message routing without capturing real user data.
- For atom-conversion findings, prove that attacker-controlled keys or values reach `String.to_atom/1` or equivalent code review evidence; do not attempt to exhaust atoms on shared infrastructure.

### Symfony Runtime query/argv proof

- Validate in a disposable copy with `register_argc_argv=On`; do not toggle debug on production.
- Show a request whose parsed query appears empty to application code while runtime argv-derived flags alter environment/debug behavior.
- Capture runtime package version, SAPI, relevant PHP setting, request target, sanitized query, and a safe observable such as a test-only environment marker.

## Reporting heuristics

- Lead with the **trust boundary that failed**, not with generic CVE language:
  - Pheditor: `dir` is a shell fragment despite `command` being allowlisted.
  - Dex: `connector_id` on token exchange bypasses per-client connector ACLs.
  - Phoenix Storybook: unauthenticated LiveView events become server-side template/code or cross-session PubSub control.
  - Symfony Runtime: two parsers disagree about whether a web query exists before reading argv flags.
- Be explicit about preconditions: authentication/role for Pheditor, leaked or test client secret for Dex token exchange, exposed storybook routes for Phoenix Storybook, and PHP/Symfony runtime settings for Symfony.
- Prefer synthetic markers and lab identities. A strong report does not need production tokens, customer files, mailbox contents, or real user session data.
- If multiple issues are present on one target, chain them carefully: exposed developer tooling or debug-mode manipulation may increase impact, but do not imply a chain unless each step is demonstrated inside scope.
