---
title: "MCP OAuth resource-metadata spoofing, markdown-sanitizer matching misses, and AI route guard parity"
---

# MCP OAuth resource-metadata spoofing, markdown-sanitizer matching misses, and AI route guard parity

A September 16 late-night GitHub wave (published 2026-09-16T22:09–22:15Z) adds three durable operator axes: **OAuth metadata that the client never binds to the server it came from**, **sanitizers that match attribute names and protocol prefixes exactly and therefore miss their siblings**, and **resource guards wired into one serving route but not its siblings**.

- **rmcp** (Rust MCP SDK, `< 2.0.0`): the OAuth Protected Resource Metadata discovery path (RFC 9728) never reads or validates the returned `resource` field — a malicious MCP server can serve metadata that names a *legitimate* server and its *legitimate* authorization server, and the client will complete a genuine consent flow and then send the resulting access token to the *attacker's* endpoint (CVE-2026-63127, [GHSA-33f5-2c5q-wgwj](https://github.com/advisories/GHSA-33f5-2c5q-wgwj)).
- **rmcp** adjacent: the Streamable HTTP server allocates a session **before** validating the request body, and every early-return path skips `close_session` — one ~250-byte unauthenticated POST permanently leaks ~400–550 bytes of server state (CVE-2026-63128, [GHSA-9pj6-vhgr-3mwh](https://github.com/advisories/GHSA-9pj6-vhgr-3mwh)).
- **@nuxtjs/mdc** (`< 0.22.1`): the default-on URL sanitizer scheme-checks only attributes named exactly `href`/`src` — SVG `xlink:href` (`javascript:`) passes through, and the `data:text/html` deny-list entries are dead code because the check compares the deny-list prefix against `url.protocol`, which is just `"data:"` for every data URI (CVE-2026-63671, [GHSA-mxm6-v9r6-r94c](https://github.com/advisories/GHSA-mxm6-v9r6-r94c)).
- **vLLM**: the audio decode-duration guard (`VLLM_MAX_AUDIO_DECODE_DURATION_S`) is threaded into **only** the `/v1/audio/transcriptions` path; the `/v1/chat/completions` `input_audio` path calls the same decoder with no limit, so a few-KB compressed file expands to multiple GB of PCM on the default-no-auth endpoint (CVE-2026-57173, [GHSA-hcwq-8wjf-3gcr](https://github.com/advisories/GHSA-hcwq-8wjf-3gcr)).

!!! warning "Lab-only validation"
    Use disposable MCP servers with fake tokens, disposable Nuxt/Vue apps with inert DOM markers, and lab vLLM workers with bounded payloads. Never complete real OAuth consent flows against third-party authorization servers, never deliver executable payloads outside your own origin, and never run amplification payloads against shared inference infrastructure.

## rmcp: RFC 9728 `resource` binding is the control that isn't

The attack shape is credential relay through metadata spoofing, not token forgery:

1. Attacker serves a malicious MCP endpoint `fake-mcp.com/mcp` with `/.well-known/oauth-protected-resource` metadata declaring `resource: real-mcp.com/mcp` and `authorization_servers:` the **legitimate** AS of the real server.
2. Victim configures any `rmcp`-based client against the attacker URL.
3. `rmcp`'s `ResourceServerMetadata` struct doesn't even include a `resource` field, so the mismatch is invisible; the client initiates OAuth with the **legitimate** AS.
4. The victim sees a genuine authorization prompt from the real IdP and approves it.
5. The issued token — valid for `real-mcp.com/mcp` — is attached to requests to `fake-mcp.com/mcp`. Full victim impersonation on the legitimate server.

Operator checks for any MCP client or OAuth client using protected-resource metadata:

1. Fetch a target's `/.well-known/oauth-protected-resource` document and check whether the `resource` field is present and identical (modulo trailing slash) to the URL you queried. Absent-or-mismatched `resource` in a **client** implementation means the client accepts AS redirection from any server metadata.
2. In a lab, stand up one disposable metadata-serving endpoint that echoes a *different* `resource` value plus an owned fake AS, and record whether the client (a) aborts, or (b) proceeds to the authorization URL — capture the constructed authorization request with the `resource`/`audience` parameter value. Use synthetic tokens only; never relay a real consent grant.
3. Generalize: this is partial-RFC-adoption — the client implements the discovery *fetch* but drops the MUST-level binding checks (RFC 9728 §3.3, §7.3). Audit any RFC 9728 / OAuth metadata implementation (including MCP gateways) by diffing spec MUST checks against the code path, not against the docs.
4. Detection-side corollary for red-team reporting: the consent prompt the victim sees is *legitimate*, so user-facing warnings don't fire — the only anomaly is the `resource`/`audience` value in the authorization request.

The session-leak sibling is the same audit family in reverse: **allocate-before-validate with cleanup-only-on-success-path**. Probe pattern (lab servers only): send a well-formed JSON-RPC POST that is *not* an `initialize` request; the server allocates a session then early-returns without closing it. Measure RSS/heap growth against request count with an in-lab rate ceiling to confirm the allocation-vs-cleanup differential. Generalize to any transport that registers state before authn/authz (compare against the Sept 16 Covenant hub and Sept 15 MCP transport pages — transport-layer capability endpoints routinely skip the authorization layer applied to the RPC layer).

## @nuxtjs/mdc: exact-name and protocol-prefix sanitizer matching misses its siblings

Two precise gaps, both default-configuration, both siblings of previously-fixed vectors (the hallmark of deny-list sanitizers):

1. **Attribute-name exactness.** `validateProp` scheme-checks `attribute === "href" || attribute === "src"`. The SVG anchor property `xLinkHref` is neither, so `<a xlink:href="javascript:...">` survives parsing and the renderer maps the property back to the real `xlink:href` attribute — click executes in the page origin. Plain `<a href="javascript:...">` is correctly stripped.
2. **Protocol-vs-prefix comparison.** `unsafeLinkPrefix` contains `data:text/html`, but the check does `url.protocol.toLowerCase().startsWith(prefix)` — and `url.protocol` is `"data:"` for every data URI, so every `data:text/*` deny-list entry is unreachable dead code. `<iframe src="data:text/html,<script>…</script>">` passes (`iframe` isn't in the render-time `dangerousTags`, which is only `["script","base"]`); execution lands in an opaque origin, but combined with vector 1 the same-origin sink is the page.

Operator checks for any markdown-to-HTML/VDOM sanitizer:

1. Build a sibling matrix from the sanitizer's own deny-list: for every blocked scheme, enumerate the alternate attribute names (`href`, `xlink:href`, `src`, `srcset`, `formaction`, `data`, `poster`, `action`) and alternate elements (`a`, `svg>a`, `iframe`, `embed`, `object`, `use`, `animate`) and confirm which pairs are actually checked.
2. Prove scheme comparison by protocol object rather than raw string: submit `data:text/html,...` and inspect the **parsed tree** (not rendered DOM) to see whether the attribute survived. A surviving `xLinkHref`/`src` property in the parse output is the bounded positive — you don't need to click it to report the gap.
3. Re-run the full original XSS matrix on any route or library with a sanitizer security history — the fix usually covers the reported vector, not the family (compare the Concrete CMS and Grav incomplete-fix follow-ups).
4. For Vue/React renderers specifically, verify the property→attribute mapping table: a property the sanitizer doesn't recognize (`xLinkHref`) may still serialize to an executable attribute.

## vLLM: media guards wired to one route, not the sibling routes

The audio decode-duration guard rejects long audio *during* decode (before allocation), but it is passed in exactly one place — the speech-to-text serving layer. The chat path chain (`parse_input_audio` → `AudioMediaIO.load_bytes` → `load_audio(..., sr=None)`) skips every guard because `max_duration_s` defaults to `None`. Inline `data:` URLs need no HTTP fetch, so the fetch-timeout env var doesn't bound them either, and the OpenAI-compatible server has no auth unless `--api-key` was set.

This is the third sibling in the same media subsystem: video frame-count bomb (CVE-2026-5497), image bomb (GHSA-pq5c-rjhq-qp7p), now audio — the guards for each landed piecemeal per-route.

Operator pattern for AI-inference endpoint recon (lab workers only):

1. Enumerate **every** route that reaches a shared decoder/parser: `/v1/chat/completions` (with `input_audio`/`image_url`/`video` content parts), `/v1/audio/transcriptions`, `/v1/embeddings`, `/invocations`, plus `data:` URL inlining vs remote-URL fetch legs.
2. For each resource limit (duration, frame count, pixel budget, decoded size), build a route × limit decision table — the finding is a limit enforced on one route and absent on a sibling that calls the same decode function.
3. Check whether inline `data:`/base64 inputs bypass the network-path controls (timeouts, size caps, DNS/IP policy) that only apply to URL fetches.
4. Prove amplification ratio only against an owned/disposable worker with monitoring and a bounded payload; record RSS delta, not production impact. Auth posture (`--api-key` set or not) is a legitimate route-level check for any engagement.

## Tracked without publication this run

- Grav `Installer::unZip()` zip-bomb/disk exhaustion (GHSA-2vcx-h8p2-9pg9 / CVE-2026-59193) — admin-authenticated DoS, tracked on the Grav page.
- node-opcua FIN-WAIT-2 socket accumulation (GHSA-r2pf-9cw4-5j65 / CVE-2026-68904) — client-side resource leak, no reusable operator workflow.
- OpenFGA `ListUsers` exclusion miss under wildcard+intersection (GHSA-g3pg-frfm-pr2m / CVE-2026-61709) — folded into the June 11 OpenFGA cache-collision page as a second authorization-decision divergence.
- Immutable.js trie-overflow DoS re-surfacing, Directus SSO user-enumeration re-surfacing, and the remaining sparse singles from the wave.

## Reporting heuristics

- For metadata-spoofing classes, report the exact metadata document served, the constructed authorization request (with `resource`/`audience` value redacted-real/synthetic-labeled), and where the issued token was observed leaving — control of the destination and disclosure of the response are separate claims.
- For sanitizer gaps, attach the parsed-tree artifact showing the surviving property plus the property→attribute mapping that makes it executable; state which sibling was previously fixed to show family incompleteness.
- For guard-parity findings, attach the decision table and the call-chain showing both routes hitting the same sink function; label DoS impact as availability unless a second sink is proven.

## September 17 follow-up: HTML deserialization parsed in the live document fires attributes before sanitization (GHSA-qrfj-mgw8-j9c6 / CVE-2026-88976)

[GHSA-qrfj-mgw8-j9c6](https://github.com/advisories/GHSA-qrfj-mgw8-j9c6) / CVE-2026-88976 (`@platejs/core` < 53.3.11, published 2026-09-17T20:32Z): Plate's core deserialization APIs parse untrusted HTML strings **in the active document** — so attributes that trigger browser behavior at parse time (image `onerror`, `<img src=x>` loads, custom-element upgrades) fire *before* the HTML is ever converted into editor nodes and before any downstream sanitization. Apps that deserialize cross-user HTML (shared docs, imported content, paste pipelines) execute script in the victim's origin at *ingest*, with no rendering step required.

- Reusable check: **for any rich-text/editor/library API that deserializes untrusted HTML, ask *where the parse happens*, not only what the sanitizer allows afterward — parsing into the live document (`innerHTML` on a detached-but-connected div, `document.createRange().createContextualFragment` on the live doc) is itself an active-content sink.** Inert contexts (`new DOMParser()`, `template` elements — inert *documents*, still-live nodes) suppress resource loads and handler firing; verify with a canary `<img src=owned-callback>` that must not produce a network request during deserialize-only, in a two-user lab where user B deserializes user A's payload.
- Same family as the `innerHTML→textContent` fake sanitizer (Sept 17 Vendure) and the `xlink:href` exact-name miss above: **the sanitizer's node/attribute model only exists after parsing — any behavior that fires during parsing bypasses it by construction.** When auditing editor deserializers, `DOMParser`/template-inertness is the control to test; `innerHTML` into a live document is the finding.

## September 18 follow-up: markdown renderer-generated attributes bypass token-filtering XSS plugins (md-editor-v3, GHSA-3rm2-h79c-8qw6 / CVE-2026-84992)

[GHSA-3rm2-h79c-8qw6](https://github.com/advisories/GHSA-3rm2-h79c-8qw6) / CVE-2026-84992 (`md-editor-v3`, PoC reproduced on 6.5.3): `MdPreview`'s registered `highlight` callback interpolates the fenced-code **language/info string** into both `class="language-${language}"` and an **unquoted** `language=${language}` attribute with no escaping. The shipped `XSSPlugin` filters only existing `html_block`/`html_inline` **parser tokens** — renderer-constructed HTML never passes through its node model — so the payload `` ```x"><details/open/ontoggle=alert(document.domain)> `` executes with the "XSS plugin" explicitly enabled. Sibling shipped-scheme miss: the legacy `.doc` renderer in `@file-viewer/doc` < 2.3.1 HTML-escaped hyperlink targets but had **no URL-scheme allowlist**, rendering live `javascript:`/`vbscript:`/`data:` links (CVE-2026-91127, [GHSA-3753-m2x2-q623](https://github.com/advisories/GHSA-3753-m2x2-q623)).

- Reusable rule: **a sanitizer that inspects parsed tokens cannot see markup the renderer builds.** When auditing markdown/highlight pipelines, fuzz the fence info-string, heading anchors, and any `class=`/attribute-construction path separately from the raw-HTML path — the plugin's own enable-state is not a negative control. Test unquoted attributes first (no `"` needed to break out: `<details/open/ontoggle=…>` survives unquoted-attribute tokenization).
- Escaping-vs-scheme axis for links: HTML-escaping a URL does not sanitize it; verify a **scheme allowlist** exists at the sink (the fixed version accepts only HTTP(S)/mail/tel/safe-relative/internal bookmarks and blocks external document links by default).
