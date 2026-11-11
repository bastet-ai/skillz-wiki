# Open WebUI model, channel, and knowledge-boundary batch

**Signal:** The **2026-05-08 20:15 UTC** advisory scan surfaced a large Open WebUI authorization batch across model routing, Ollama passthrough APIs, knowledge-base access, channel membership, Socket.IO state, Redis cache namespacing, LDAP login, and mass assignment.

## Advisory cluster

All listed advisories affect `open-webui <= 0.8.12` according to GitHub metadata:

- **Knowledge/file and RAG boundaries**, [GHSA-h36f-rqpx-j5wx](https://github.com/advisories/GHSA-h36f-rqpx-j5wx), [GHSA-6c2x-gcp3-gp73](https://github.com/advisories/GHSA-6c2x-gcp3-gp73), [GHSA-7r82-qhg4-6wvj](https://github.com/advisories/GHSA-7r82-qhg4-6wvj): unauthorized file/knowledge content access, global KB enumeration, and collection overwrite leading to destruction or RAG poisoning.
- **Channel and collaborative-document access**, [GHSA-hmgr-67hw-j2cq](https://github.com/advisories/GHSA-hmgr-67hw-j2cq), [GHSA-vrfh-rj4q-rmhr](https://github.com/advisories/GHSA-vrfh-rj4q-rmhr), [GHSA-c7wp-3qh5-55pv](https://github.com/advisories/GHSA-c7wp-3qh5-55pv), [GHSA-7rjh-px4v-5w55](https://github.com/advisories/GHSA-7rjh-px4v-5w55): deactivated channel members, read-only users, missing member checks, and access-grant filter bypasses.
- **Model and tool execution boundaries**, [GHSA-rcvp-6fgw-c7fh](https://github.com/advisories/GHSA-rcvp-6fgw-c7fh), [GHSA-mqq6-cqcx-38vg](https://github.com/advisories/GHSA-mqq6-cqcx-38vg), [GHSA-hp5m-24vp-vq2q](https://github.com/advisories/GHSA-hp5m-24vp-vq2q), [GHSA-9vvh-qmjx-p4q8](https://github.com/advisories/GHSA-9vvh-qmjx-p4q8): Ollama API bypasses, model import overwrite, responses passthrough authorization gaps, and model chaining access-control bypass.
- **Session/cache/account-state boundaries**, [GHSA-3x8w-4f7p-xxc2](https://github.com/advisories/GHSA-3x8w-4f7p-xxc2), [GHSA-45m8-cpm2-3v65](https://github.com/advisories/GHSA-45m8-cpm2-3v65), [GHSA-hr43-rjmr-7wmm](https://github.com/advisories/GHSA-hr43-rjmr-7wmm), [GHSA-2r4p-jpmg-48f4](https://github.com/advisories/GHSA-2r4p-jpmg-48f4): cross-instance Redis cache poisoning, stale admin Socket.IO role state, Pydantic `extra='allow'` mass assignment, and LDAP empty-password authentication bypass.

## Why this matters

AI web consoles collapse many trust zones: user documents, shared channels, model registries, vector collections, tool servers, and external model APIs. If each endpoint reimplements authorization, one passthrough or stale realtime session becomes a broad data/control-plane bypass.

## Triage

1. Patch Open WebUI beyond `0.8.12` as soon as fixed packages are available; otherwise isolate or disable exposed risky features until patched.
2. Rotate LDAP and admin sessions for deployments where empty-password or stale-role risks may have been reachable.
3. Review access logs for direct calls to `/api/generate`, `/api/embed`, `/api/embeddings`, `/api/show`, responses passthrough, model import, KB metadata, and Socket.IO document/channel events.
4. Inspect vector collections and model registry entries for unauthorized overwrites, poisoning, or unexpected ownership.

## Durable controls

- Put one authorization gate in front of every model, vector, document, channel, and passthrough operation; do not rely on UI filtering.
- Revalidate role, membership, deactivation, and ownership on every realtime event and long-lived socket action.
- Namespace cache keys by tenant/deployment/user where appropriate.
- Reject unknown request fields by default; avoid permissive schema modes for authorization-relevant objects.
- Treat model chaining and tool passthrough as delegation: the caller must be allowed to reach every downstream model/tool.

## July 24 follow-up: channel, realtime, knowledge, and delegated-execution boundaries

Open WebUI 0.10.0 closes another cross-surface authorization wave. The durable operator lesson is to bind every supplied object or session identifier to both the authenticated principal and the URL/body parent object, then repeat that decision at asynchronous emitters and workers.

Sources:

- [GHSA-gh7p-78x6-jw6m](https://github.com/advisories/GHSA-gh7p-78x6-jw6m): channel member responses expose full user settings, including integration credential fields.
- [GHSA-73x5-h92w-xc2j](https://github.com/advisories/GHSA-73x5-h92w-xc2j): a thread parent is loaded by message ID without binding it to the authorized URL channel.
- [GHSA-3wp3-xxj9-5jqq](https://github.com/advisories/GHSA-3wp3-xxj9-5jqq): a callable passed as aiocache's static `key=` makes permission-filtered model lists collide across users.
- [GHSA-7r7x-gjvr-448g](https://github.com/advisories/GHSA-7r7x-gjvr-448g): upload `metadata.knowledge_id` inserts a knowledge/file association before the later write check.
- [GHSA-74h3-cxq7-vc5q](https://github.com/advisories/GHSA-74h3-cxq7-vc5q): a caller-controlled Socket.IO session ID can route code-interpreter or tool events into another user's connected browser session.
- [GHSA-x2ff-v5v8-m75m](https://github.com/advisories/GHSA-x2ff-v5v8-m75m): chat-completion `id` and multimodel `message_ids` can write across channel boundaries.
- [GHSA-855v-hq7w-jmjw](https://github.com/advisories/GHSA-855v-hq7w-jmjw): Redis-revoked JWTs remain accepted by Socket.IO and terminal WebSocket authentication.
- [GHSA-gmfw-g93r-vg53](https://github.com/advisories/GHSA-gmfw-g93r-vg53): unauthenticated collaborative-document awareness and leave events accept spoofed identity/document data.
- [GHSA-rqj7-6wrp-6g2g](https://github.com/advisories/GHSA-rqj7-6wrp-6g2g): the direct image-edit route skips global and per-user capability gates.
- [GHSA-mvx4-532p-xfm9](https://github.com/advisories/GHSA-mvx4-532p-xfm9): scheduled automations do not revalidate deactivated owners, feature grants, or stored-model access.
- [GHSA-4r2p-27mh-5m22](https://github.com/advisories/GHSA-4r2p-27mh-5m22): shared Pyodide snippets run in a same-origin worker and can make credentialed requests when a victim clicks **Run**.

### Two-user channel and object-binding matrix

Use two ordinary users, one admin only where a privilege boundary must be observed, private and shared channels, a read-only knowledge base, synthetic model names, and marker-only messages/files. Never capture tool keys, real prompts, provider content, or third-party credentials.

| Surface | Positive test | Secure control |
| --- | --- | --- |
| channel members | ordinary member receives only public profile fields | settings, webhooks, and tool-server keys absent |
| thread parent | attacker channel plus victim marker message ID | parent rejected unless `parent.channel_id` matches URL channel |
| model cache | alternate two users with distinct canary model grants inside the TTL | each response remains principal-scoped |
| KB upload | read-only user supplies target `knowledge_id` in upload metadata | no association committed; failed vector processing leaves no row |
| message update | mix attacker/victim IDs in single and multimodel completion forms | every ID is bound to the selected channel before emitter write |
| image edit | verified user denied image generation calls direct edit route | request rejected before provider dispatch |

For ID-based checks, use IDs created by the lab harness; do not enumerate UUIDs. Capture the URL parent, supplied child ID, database parent/owner before and after, status, and 0.10.0 negative control.

### Realtime identity and lifecycle replay

1. With Redis enabled, issue a disposable JWT containing a unique `jti`; prove HTTP and Socket.IO access before revocation.
2. Sign out or perform a lab back-channel logout, then attempt a **new** HTTP, Socket.IO, note/channel join, and terminal-WebSocket handshake with the same token. Every transport should reject it.
3. Connect an unauthenticated socket and emit only a harmless synthetic awareness marker for a disposable note. No event should reach the legitimate room, and spoofed `user_id` values must not be trusted.
4. Create an automation that writes only a run counter, then change its owner to `pending` or remove the automation/model grant. At the next due time, the counter must remain unchanged.

Report transport and lifecycle drift explicitly: **the same revoked/deactivated principal is denied on the normal HTTP path but accepted by a realtime or background path**.

### Session-ID delegation and Pyodide trust

The cross-user event-caller issue requires code interpreter/tool reachability, a victim socket ID (for example from a shared-note collaboration room), and a connected victim. Prove it only with two disposable users and an inert browser-side tool that increments a visible counter. Show that user A can cause an event to arrive at user B's session on an affected build and that 0.10.0 binds the destination session to the requester. Do not invoke Functions, create server-side code, or target an administrator session.

For Pyodide, require all preconditions: shared attacker-controlled code, Pyodide selected, and a victim click on **Run**. In an isolated browser profile, let the snippet request a same-origin endpoint that only records a canary counter. Record origin, cookie-send decision, CORS result, and counter. On 0.10.0's opaque-origin sandbox the request must carry no application credential and must not change the counter. Do not read session state or call privileged APIs.

### Evidence standard

A strong report includes exact version and feature flags, two-user/role setup, raw IDs and their server-side parent bindings, cache or transport timing, authorization decisions at both request and asynchronous sink, marker-only before/after state, and the 0.10.0 result. Avoid elevating model-name disclosure, UI presence spoofing, billing-only image dispatch, or bounded stale automation into account takeover unless a stronger application-specific sink is independently proven.

## Late July 24 follow-up: terminal, model, file, and fetch-policy boundaries

Five more Open WebUI advisories extend the same 0.10.0 comparison fixture:

- [GHSA-frvj-c5qp-xj4w](https://github.com/advisories/GHSA-frvj-c5qp-xj4w) / CVE-2026-59221: terminal proxy traversal decoding stops after eight passes, so a ninth encoding layer can defer `..` normalization to the upstream.
- [GHSA-j657-m4c4-24jq](https://github.com/advisories/GHSA-j657-m4c4-24jq) / CVE-2026-59224: the WebSocket terminal `session_id` can inject query material before the proxy-appended `user_id`; the broader HTTP design also forwards an unsigned `X-User-Id` identity claim.
- [GHSA-m3qf-58wf-w979](https://github.com/advisories/GHSA-m3qf-58wf-w979) / CVE-2026-59225: task routes authorize an arena wrapper, then recursively dispatch to a restricted selected model with `bypass_filter=True`.
- [GHSA-2xwm-4h2q-ggfx](https://github.com/advisories/GHSA-2xwm-4h2q-ggfx) / CVE-2026-59212: a file readable through a knowledge-base grant can be attached to an attacker-owned model, after which model metadata satisfies later write/delete authorization.
- [GHSA-qg3f-8x3j-ggf2](https://github.com/advisories/GHSA-qg3f-8x3j-ggf2) / CVE-2026-59223: `WEB_FETCH_FILTER_LIST` compares suffixes against a full URL or without DNS-label boundaries, confusing a path suffix or `evilcorp.com` with an allowed `corp.com` host.

### Bounded replay matrix

1. Configure a lab terminal upstream with `/base/ok` and `/admin/canary`, fake credentials, and request logging. Compare canonical, one-layer, eight-layer, and nine-layer traversal-shaped paths. Evidence is the upstream path and marker status only; do not invoke a shell or terminal action.
2. For WebSocket identity, create two disposable users and terminal sessions. Put reserved query separators in only the lab `session_id`, then record the first/last `user_id` values seen by a mock coordinator. Also test direct upstream access separately: an unsigned `X-User-Id` is exploitable only where that upstream is independently reachable and trusts it.
3. Give an ordinary user access to a synthetic arena wrapper but deny its underlying canary model. Compare direct model, normal chat, and `/api/v1/tasks/moa/completions`; the owned provider stub must not receive a restricted-model dispatch on 0.10.0.
4. Give the user read-only access to a KB containing one marker file. Attempt to attach that known file ID to the user's model, then perform only a reversible marker metadata update. Do not delete files or enumerate IDs.
5. For the web-fetch filter, use owned public hosts named to exercise exact host, subdomain, suffix-collision, and path-suffix cases. This issue does not defeat Open WebUI's separate default non-global-IP guard; do not claim private-address SSRF without independently proving that guard is disabled or bypassed.

Report the transitions narrowly: **deferred decode -> upstream path escape**, **unencoded session path -> query identity injection**, **authorized wrapper -> unauthorized selected model**, **read-only file relation -> write decision**, or **raw URL suffix -> wrong host-policy result**. Affected terminal/file paths begin in 0.9.6 and are fixed in 0.10.0; the arena path affects 0.8.12 through pre-0.10.0 builds.

## August 4 follow-up: alternate feature paths and message authorship

Two 0.11.0 advisories add an operation-path test to the existing channel/model fixture:

- [GHSA-g423-grf7-98rv / CVE-2026-70484](https://github.com/advisories/GHSA-g423-grf7-98rv): a caller denied image generation can set the legacy chat-completion feature flag and still reach the configured image provider.
- [GHSA-mj5r-jf49-m3w7 / CVE-2026-70481](https://github.com/advisories/GHSA-mj5r-jf49-m3w7): standard-channel write access is accepted as authority to update or delete another member's message.

Use a fake image provider that only records dispatch and a standard channel with two disposable members and marker-only messages. Compare the direct image routes, native function calling, and legacy chat-completion path with image generation globally disabled/enabled and per-user allowed/denied. The secure result is the same permission decision at every dispatch path; a client `features` object is intent, not authorization. Do not generate an image or spend provider quota.

For channels, compare own-message and other-member update/delete across standard, group, direct-message, read-only, and writable channels. Replace update/delete persistence with no-op recorders. Capture channel type, membership grant, operation, message author, caller, and sink reachability. A bounded positive is **ordinary standard-channel writer -> victim marker message ID -> no-op update/delete sink runs without an authorship decision**. Do not delete or forge retained messages, and keep the nearby cross-chat generation-cancellation record out of this workflow because it provides only availability impact.
