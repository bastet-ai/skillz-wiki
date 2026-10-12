# Open WebUI auth, session, and API authorization-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15, with OAuth client-binding, terminal-preview origin, transport-role, shared-folder deletion, tool-source, and render-error follow-ups added on 2026-08-04.

This batch is durable because it is not one bug class: it is the same authorization mistake repeated across tools, shared chat, background tasks, completions, channels, collaborative documents, folders, LDAP/OAuth bootstrap, Socket.IO sessions, and API-key handling. Client-visible role, read permission, shared-chat state, or endpoint restrictions are not authorization unless each mutation and backend worker enforces the intended subject-object-action tuple.

## Advisories covered

- **Open WebUI: Missing `workspace.tools` Authorization Check on Tool Update Endpoint Allows Privilege Escalation to Code Execution** — [GHSA-p4fx-23fq-jfg6](https://github.com/advisories/GHSA-p4fx-23fq-jfg6) / CVE-2026-45395 (high).
- **Open WebUI: LDAP and OAuth First-User Race Condition Allows Multiple Admin Accounts** — [GHSA-h3ww-q6xx-w7x3](https://github.com/advisories/GHSA-h3ww-q6xx-w7x3) / CVE-2026-45675 (high).
- **Open WebUI: shared-chat branch ignores access_type, allowing unauthorized file deletion** — [GHSA-26g9-27vm-x3q8](https://github.com/advisories/GHSA-26g9-27vm-x3q8) / CVE-2026-45671 (high).
- **Open WebUI: Low-privilege authenticated users can enumerate and stop global background tasks, causing system-wide chat disruption** — [GHSA-8jjp-r2w2-4v22](https://github.com/advisories/GHSA-8jjp-r2w2-4v22) / CVE-2026-45399 (high).
- **Open WebUI has an IDOR vulnerability in the pin_channel_message API endpoint** — [GHSA-5gc6-xhv4-2wg6](https://github.com/advisories/GHSA-5gc6-xhv4-2wg6) / CVE-2026-45386 (medium).
- **Open WebUI has an IDOR vulnerability in the update_message_by_id API endpoint** — [GHSA-wwhq-cx22-f7vv](https://github.com/advisories/GHSA-wwhq-cx22-f7vv) / CVE-2026-45385 (medium).
- **Open WebUI has Broken Access Control for Completions API** — [GHSA-gfm2-xm6c-37qc](https://github.com/advisories/GHSA-gfm2-xm6c-37qc) / CVE-2026-45349 (high).
- **Open WebUI's API key endpoint restrictions bypassed via `x-api-key` header — full message processing on restricted endpoints** — [GHSA-57q6-fvp4-pqmm](https://github.com/advisories/GHSA-57q6-fvp4-pqmm) / CVE-2026-45339 (medium).
- **Open WebUI: Deactivated Channel Members Retain Full Access to Group/DM Channels** — [GHSA-hmgr-67hw-j2cq](https://github.com/advisories/GHSA-hmgr-67hw-j2cq) / CVE-2026-44561 (medium).
- **Read-Only Open WebUI Users Can Modify Collaborative Documents via Socket.IO** — [GHSA-vrfh-rj4q-rmhr](https://github.com/advisories/GHSA-vrfh-rj4q-rmhr) / CVE-2026-44564 (medium).
- **Open WebUI Missing Access Check on Channel Members Endpoint for Standard Channels** — [GHSA-c7wp-3qh5-55pv](https://github.com/advisories/GHSA-c7wp-3qh5-55pv) / CVE-2026-44559 (medium).
- **Open WebUI's Channel Access Grants Bypass filter_allowed_access_grants** — [GHSA-7rjh-px4v-5w55](https://github.com/advisories/GHSA-7rjh-px4v-5w55) / CVE-2026-44558 (medium).
- **Open WebUI's responses passthrough endpoint lacks access control authorization** — [GHSA-hp5m-24vp-vq2q](https://github.com/advisories/GHSA-hp5m-24vp-vq2q) / CVE-2026-44556 (high).
- **Open WebUI: Stale Admin Role in Socket.IO Session Pool Enables Post-Demotion Cross-User Note Access** — [GHSA-45m8-cpm2-3v65](https://github.com/advisories/GHSA-45m8-cpm2-3v65) / CVE-2026-44553 (high).
- **Open WebUI's Mass Assignment via Pydantic extra='allow' Allows Creating Folders in Other Users' Accounts** — [GHSA-hr43-rjmr-7wmm](https://github.com/advisories/GHSA-hr43-rjmr-7wmm) / CVE-2026-44550 (medium).
- **Open WebUI has an LDAP Empty Password Authentication Bypass** — [GHSA-2r4p-jpmg-48f4](https://github.com/advisories/GHSA-2r4p-jpmg-48f4) / CVE-2026-44551 (critical).
- **Open WebUI OAuth token exchange accepts tokens minted for another client** — [GHSA-rq84-p6rr-vf89](https://github.com/advisories/GHSA-rq84-p6rr-vf89) / CVE-2026-70482 (high).
- **Open WebUI terminal file preview collapses iframe origin isolation** — [GHSA-3xpf-xq7r-v8c5](https://github.com/advisories/GHSA-3xpf-xq7r-v8c5) / CVE-2026-70486 (high).
- **Open WebUI shared-subfolder deletion crosses from write grant to owner chat destruction** — [GHSA-3cg5-48j3-v4gv](https://github.com/advisories/GHSA-3cg5-48j3-v4gv) / CVE-2026-70494 (high).
- **Open WebUI KaTeX error fallback reparses message source as HTML** — [GHSA-pwxh-7358-jq2x](https://github.com/advisories/GHSA-pwxh-7358-jq2x) / CVE-2026-70492 (high).
- **Open WebUI read-only tool responses disclose server-side source** — [GHSA-3r7g-q6cg-q2vx](https://github.com/advisories/GHSA-3r7g-q6cg-q2vx) / CVE-2026-70491 (medium).
- **Open WebUI terminal WebSocket omits the verified-role gate** — [GHSA-5gpj-vj23-vhhv](https://github.com/advisories/GHSA-5gpj-vj23-vhhv) / CVE-2026-70490 (medium).

## Operator triage

1. Inventory Open WebUI deployments that allow self-service login, LDAP/OAuth bootstrap, API keys, collaborative documents, channel sharing, background task control, tool editing, or shared-chat file operations.
2. Test least-privileged accounts against completions, responses passthrough, tool update, task stop/list, channel member, pin/update message, folder create, and shared-chat deletion paths; confirm demoted/deactivated users lose websocket and channel access immediately.
3. Review auth logs for empty-password LDAP attempts, multiple first-admin creations, unexpected admin/socket sessions after demotion, API-key use on restricted endpoints, and non-owner modifications of channels, folders, tools, or documents.
4. If unauthorized admin/tool/code-execution access is suspected, rotate tool secrets, OAuth/LDAP credentials, API keys, and model/provider tokens; invalidate sessions and websocket pools.

## Durable controls

- Authorization checks must be centralized and action-specific, but enforced at every transport: REST, Socket.IO, background workers, tool update flows, shared-chat branches, and model/completion passthroughs.
- Role changes and deactivation must revoke live websocket/session state, cached role claims, channel grants, and background-worker authority immediately.
- API keys are principals, not bypass tokens. Endpoint restrictions must be checked after all alternate header names, compatibility routes, and proxy/pass-through paths normalize credentials.
- First-user/bootstrap logic needs a transaction or one-time server-side lock; external identity providers do not make race-prone admin creation safe.
- Mass assignment protections should default to reject extra fields and derive owner/workspace from authenticated server context, never from caller JSON.

## August 4 follow-up: bind bearer proofs to the client and preview origin

The token-exchange record applies only when `ENABLE_OAUTH_TOKEN_EXCHANGE` is enabled. A successful provider `userinfo` call proves that a token is valid for a user; it does not prove that the token was minted for Open WebUI's OAuth client. Test this with a mock OIDC provider, two synthetic client IDs, and one disposable subject. Mint inert test tokens for the same subject under each client and record the provider's `client_id`, subject, Open WebUI trust-list decision, and session-issuance result.

The secure matrix is: own client accepted, foreign client rejected, invalid token rejected, disallowed-domain subject rejected, and no session created from a token whose client cannot be established. Do not obtain a real user's token or target a public provider. The advisory notes that 0.11.0 requires a correctly configured `OAUTH_TOKEN_EXCHANGE_TRUSTED_CLIENT_IDS`; providers without usable RFC 7662 introspection have no safe token-exchange configuration, so test the actual deployment mode rather than treating upgrade alone as proof.

The terminal-preview record is a separate browser-origin chain. It requires a configured terminal server and a user able to place a file there. Use two disposable users, an HTML file containing only a script that changes a visible random DOM marker, and a terminal proxy with fake headers. Never read `localStorage`, cookies, or session tokens. Compare the `serveUrl` and `srcdoc` branches, `iframeSandboxAllowSameOrigin` on/off, restrictive synthetic CSP on/off, and victim/non-victim origins.

A bounded positive is **terminal-served preview loads under the application origin with both `allow-scripts` and `allow-same-origin` -> inert child script changes the parent marker automatically**. Capture iframe URL/origin, sandbox tokens, CSP, event that opened the preview, and parent-access decision. Open WebUI lists 0.11.0 as fixed; the default fixed path should give the served document an opaque origin unless same-origin behavior was explicitly enabled.

## August 4 follow-up: test every transport, grant tier, cascade, and error renderer

Four additional records show different ways a valid preliminary decision can authorize too much at the sink. Use Open WebUI 0.10.2 as the affected comparison and 0.11.0 as the corrected build; the terminal WebSocket path begins in 0.8.8 and the folder cascade requires folder sharing plus a write grant.

### Transport-role parity

Create approved, pending, and deactivated disposable users. Configure a terminal adapter that records session-open attempts but never starts a shell, and grant it to a synthetic group. Compare HTTP terminal routes, the terminal WebSocket first-message JWT path, Socket.IO, expired/revoked tokens, and group membership retained/removed after deactivation.

A positive is **pending or deactivated user is rejected by HTTP -> the same token and grant reach the no-op WebSocket session opener**. Record token status only as valid/expired/revoked, never the token itself. This finding does not imply a terminal-grant bypass: preserve whether the account still had public/group access and report the missing verified-role decision separately.

### Grant-to-cascade and response-projection matrices

Seed an owner folder with one child and marker-only chats, then grant another user read or write access. Replace move, chat delete, subtree delete, and persistence with no-op recorders. Compare root versus child folder, owner versus collaborator, read versus write, `delete_contents` false/true, and caller-owned versus owner-owned descendants. The strong boundary is **write collaborator selects owner child -> cascade recorder receives owner chat IDs without an owner/admin decision**. Never delete retained chats.

For tools, seed source containing a random non-secret marker and expose only function specifications to a read-only user. Compare owner, writer, reader, public-reader, and no-grant callers across list, compact list, per-ID, export, and execution paths. Capture returned field names and a hash/presence bit for the marker. A reader may invoke an intentionally shared tool, but its source must not leak through a response-model subclass, extra-field behavior, or full-model spread. Do not place credentials or operational URLs in the fixture.

### Error-path render boundary

The KaTeX record is not a generic Markdown success-path test: a renderer exception caused the original math source to reach an HTML sink. In a detached browser fixture with no sessions, use a short deterministic test double that makes the math renderer throw and puts only an inert DOM-marker element in the source. Compare parse error, resource/stack-style exception, success, shared chat, and channel rendering. Instrument text insertion versus HTML insertion and block all scripts.

A bounded positive is **renderer throws -> raw source reaches the HTML parser -> inert element appears**, not JavaScript execution or token access. Capture input provenance, exception class, fallback value, escaping state, and final DOM nodes. Generalize the check to syntax highlighters, charting, diagram, media, and preview components: sanitizer and escaping policy must apply to every catch/fallback branch as well as normal output.

## October 12 follow-up: Open WebUI 0.11.4 wave — WS-first-message-only revocation, disabled-backend index reachability, and read-only tool source export (fixed 0.11.4)

- **Terminal WebSocket revokes at handshake, never again** ([GHSA-wqjg-w22m-7835](https://github.com/advisories/GHSA-wqjg-w22m-7835)/CVE-2026-109289): the terminal proxy route in `terminals.py` checks user access **only on the first message**, so a deactivated user with an already-open terminal WS keeps executing commands and reading/writing files on the terminal server. Fourth sighting of the revocation-lifecycle axis this month (Vikunja webhook cleanup, Grav disabled-account API, pyLoad auth-cache) — the standing rule holds: **long-lived transports must re-assert authorization on a cadence or per-message; test "deactivate account → keep using open channel" on every WS/SSE/STOMP product.**
- **Explicit backend-index reaches disabled provider backends with configured keys attached** ([GHSA-32hx-qqmp-8j8q](https://github.com/advisories/GHSA-32hx-qqmp-8j8q)/CVE-2026-109296): Ollama/OpenAI-compatible listing routes accept a backend index as path segment or query param; disabled backends stay reachable, fire requests carrying their configured API keys, and disclose version strings + connection inventory to any authenticated user. Rule: "disabled/tombstoned" config entries are a route-parameter sweep target — enumerate index/id values, don't trust the listing UI to hide what the handler will still serve.
- **`GET /api/v1/tools/export` returns full Python source of read-only shared tools** ([GHSA-7rgv-j27q-wxqf](https://github.com/advisories/GHSA-7rgv-j27q-wxqf)/CVE-2026-109294): tool export permission ignores the read-only sharing mode, leaking embedded API keys/credentials in tool code. Read-vs-step-up asymmetry on an export-family endpoint (same genealogy as Keycloak installation/registration exports).
- Remaining legs (stored XSS in model notes, tools/pipelines info-disclosure, ReDoS, automation DoS, resource consumption) are class-covered — recorded, not expanded.
