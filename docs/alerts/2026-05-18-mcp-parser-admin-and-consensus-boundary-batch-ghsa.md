# MCP, parser, admin, and consensus-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-3h63-fx68-x5fm](https://github.com/advisories/GHSA-3h63-fx68-x5fm),
[GHSA-h9hm-m2xj-4rq9](https://github.com/advisories/GHSA-h9hm-m2xj-4rq9),
[GHSA-cmxg-94mg-jq94](https://github.com/advisories/GHSA-cmxg-94mg-jq94),
[GHSA-cwfq-rfcr-8hmp](https://github.com/advisories/GHSA-cwfq-rfcr-8hmp),
[GHSA-5gm9-622f-qcg5](https://github.com/advisories/GHSA-5gm9-622f-qcg5),
[GHSA-fvh2-gm75-j4j7](https://github.com/advisories/GHSA-fvh2-gm75-j4j7),
[GHSA-ch88-c67q-65r9](https://github.com/advisories/GHSA-ch88-c67q-65r9),
[GHSA-42h5-h8qh-vv9v](https://github.com/advisories/GHSA-42h5-h8qh-vv9v),
[GHSA-32p9-57cr-4x65](https://github.com/advisories/GHSA-32p9-57cr-4x65),
[GHSA-3cjv-h753-qf7h](https://github.com/advisories/GHSA-3cjv-h753-qf7h),
[GHSA-qp7v-gjgg-4mj6](https://github.com/advisories/GHSA-qp7v-gjgg-4mj6),
[GHSA-hv23-4qp7-8c8r](https://github.com/advisories/GHSA-hv23-4qp7-8c8r),
[GHSA-xp7r-j8r6-j9h3](https://github.com/advisories/GHSA-xp7r-j8r6-j9h3),
[GHSA-fmxf-pm6p-7xgm](https://github.com/advisories/GHSA-fmxf-pm6p-7xgm),
[GHSA-3v9w-6365-9w54](https://github.com/advisories/GHSA-3v9w-6365-9w54),
[GHSA-9rh9-hf3w-9fgg](https://github.com/advisories/GHSA-9rh9-hf3w-9fgg),
[GHSA-f946-9qp6-vgch](https://github.com/advisories/GHSA-f946-9qp6-vgch),
[GHSA-w8j3-pq8g-8m7w](https://github.com/advisories/GHSA-w8j3-pq8g-8m7w),
[GHSA-gqr2-7hcg-rchf](https://github.com/advisories/GHSA-gqr2-7hcg-rchf),
[GHSA-mc57-h6j3-3hmv](https://github.com/advisories/GHSA-mc57-h6j3-3hmv),
[GHSA-jxxr-4gwj-5jf2](https://github.com/advisories/GHSA-jxxr-4gwj-5jf2), and
[GHSA-245j-xjvr-xvm5](https://github.com/advisories/GHSA-245j-xjvr-xvm5).

This batch is durable because the same operational mistakes keep reappearing: local developer/agent services are exposed as browser-reachable APIs, parser and protocol boundaries let malformed input become consensus divergence or resource exhaustion, object-path helpers trust attacker-controlled key paths, and admin consoles authorize actions after rendering or resolving privileged objects.

## What changed

- **Zebra / zebrad** fixed two consensus-impacting issues before 4.4.0: gossip queue and syncer poisoning could halt block discovery, and transparent `SIGHASH_SINGLE` handling diverged from `zcashd` for corresponding outputs.
- **dynoxide** patched MCP HTTP transport exposure in 0.9.13; DNS rebinding plus cross-origin CSRF could let a malicious page drive a local MCP service.
- **MLflow** fixed an unauthenticated arbitrary-file-read path before 3.10.0. This is separate from the webhook SSRF item observed earlier in the day and reinforces that tracking servers need both network and filesystem boundaries.
- **Dozzle** disclosed pre-auth SSRF with response-body reflection through the notification test-webhook path in default no-auth deployments.
- **Crabbox** fixed Islo provider workspace path traversal before 0.9.0; workspace names and resolved paths must stay under the intended root.
- **@steipete/summarize** fixed local credential exposure of bearer tokens and API keys stored in `~/.summarize/daemon.json` before 0.15.0.
- **aiwaves-cn agents** had unbounded memory recall in `recall_relevant_memories_to_working_memory`, making memory stores another resource-exhaustion input.
- **cowlib** fixed both excessive allocation in `cow_http_te` and CRLF/SSE event injection through unvalidated field values in 2.16.1.
- **iskorotkov/avro** added more decoder fixes in 2.33.0: CPU exhaustion and integer overflow, complementing the map-allocation limit guidance from the previous Avro advisory.
- **brace-expansion** fixed a large numeric-range DoS where documented `max` protection could be bypassed in 5.0.6.
- **@tmlmobilidade/utils** and **parse-nested-form-data** fixed prototype-pollution paths through nested key assignment / `FormData` field names.
- **async-http-client** fixed credential leakage on cross-origin redirects by stripping the `Cookie` header in 2.15.0 and 3.0.10.
- **LibreNMS**, **CI4MS**, and **shopper/framework** added web-admin lessons: stored/reflected XSS, unsafe fileeditor destructive operations, Livewire admin authorization bypass, and race conditions on discount usage limits.
- **omec-project AMF** could crash on malformed LocationReports; treat telecom/core-network message parsers like other hostile network parsers even when the severity is low.

The CI4MS pages-module XSS advisory was already represented in the prior auth/render batch; it remains listed here because the updated advisory window also included a distinct CI4MS Fileeditor destructive-operation boundary.

## Operator triage

1. Patch first where exposed to browsers or untrusted tenants: dynoxide MCP HTTP transports, MLflow tracking servers, Dozzle no-auth deployments, Livewire/admin consoles, and local summarizer daemons on shared developer hosts.
2. Upgrade protocol/parser libraries on any public ingestion path: Zebra 4.4.0+, cowlib 2.16.1+, Avro 2.33.0+, brace-expansion 5.0.6+, async-http-client 2.15.0/3.0.10+, and the fixed prototype-pollution packages.
3. For Zebra or any consensus client, run mixed-version canaries and replay known edge-case transactions/messages before rolling patches across validators, relays, or indexers.
4. For MLflow, Dozzle, and MCP tools, assume URL submission can become SSRF and local-service control. Require auth, bind local-only services to loopback with origin/CSRF checks, and block private, loopback, link-local, metadata, and redirect targets.
5. For admin consoles, deny by default on every action method, not just the menu or rendered component. Race-test quotas, usage counters, and coupon/discount decrement paths.
6. For local CLI daemons, store bearer tokens with owner-only permissions, avoid serving credential-bearing config through debug endpoints, and rotate keys if vulnerable versions ran on multi-user systems.

## Replayable validation boundaries

- **MCP/local service boundary:** open a hostile browser page that attempts DNS rebinding, cross-origin POSTs, and simple-form CSRF against dynoxide or similar MCP HTTP endpoints; every command-bearing route must require an unforgeable origin/session boundary.
- **SSRF boundary:** submit webhook URLs using redirects, decimal/octal IPs, IPv6-mapped loopback, DNS rebinding, and metadata hosts to Dozzle/MLflow-style endpoints; no backend request or reflected response may reach blocked networks.
- **Filesystem boundary:** feed `../`, symlink, alternate separator, Unicode-normalized, and absolute path variants through Crabbox Islo workspaces and CI4MS Fileeditor actions; resolution must stay under the configured root and deny dangerous extensions/targets before rename/delete.
- **Parser/resource boundary:** replay malformed LocationReports, Avro integer/CPU fixtures, cow transfer-encoding bombs, brace ranges, and ai memory-recall payloads inside constrained workers; failures must be bounded and observable without process-wide crash.
- **Prototype boundary:** parse nested `__proto__`, `constructor.prototype`, and mixed array/object field names through affected form/key-path helpers; inherited object state must not change.
- **Redirect credential boundary:** redirect async-http-client requests across scheme/host/port boundaries; cookies and auth headers must be stripped unless an explicit same-site policy permits forwarding.
- **Admin authorization boundary:** call Livewire component methods, config display routes, and destructive file operations directly with low-privilege users; action handlers must repeat permission checks and optimistic-lock quota updates.

## Durable controls

- Treat localhost HTTP transports for agents and MCP servers as externally reachable once a browser can make requests; require auth, CSRF protection, strict Origin checks, and non-predictable session binding.
- Centralize URL egress policy and apply it after canonicalization, every redirect, and final socket resolution.
- Keep parser workers boring: small memory/CPU limits, timeouts, no filesystem/network unless required, and crash-only isolation for telecom, crypto, archive, and serialization formats.
- Never implement nested object assignment by writing raw user keys into prototypes or inherited objects; block meta keys before recursion.
- Scope file operations with realpath/root containment and an allowlist of permitted extensions and verbs; authorize before path resolution side effects.
- Test admin component methods and background action endpoints directly, not only through the UI paths that normally hide them.
- Make counters and quotas atomic at the storage boundary so concurrent redemption cannot exceed policy.
