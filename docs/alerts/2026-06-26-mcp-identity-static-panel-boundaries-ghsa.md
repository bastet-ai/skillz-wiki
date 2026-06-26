# MCP, identity, static-path, and panel boundary checks

Source: hourly offensive-security scan, 2026-06-26. Primary entries: GitHub Advisory Database [GHSA-rp72-5v5q-2446](https://github.com/advisories/GHSA-rp72-5v5q-2446), [GHSA-73cv-556c-w3g6](https://github.com/advisories/GHSA-73cv-556c-w3g6) / CVE-2026-49257, [GHSA-2r68-g678-7qr3](https://github.com/advisories/GHSA-2r68-g678-7qr3) / CVE-2026-49291, [GHSA-jv46-xfwm-36j7](https://github.com/advisories/GHSA-jv46-xfwm-36j7) / CVE-2026-49454, [GHSA-wpvj-hjcr-h3p2](https://github.com/advisories/GHSA-wpvj-hjcr-h3p2) / CVE-2026-48820, [GHSA-3p34-w4f6-5xh2](https://github.com/advisories/GHSA-3p34-w4f6-5xh2), [GHSA-pw9p-jvrm-f7rm](https://github.com/advisories/GHSA-pw9p-jvrm-f7rm) / CVE-2026-48979, [GHSA-rhq6-9rgh-v45c](https://github.com/advisories/GHSA-rhq6-9rgh-v45c), [GHSA-f65r-h4g3-3h9h](https://github.com/advisories/GHSA-f65r-h4g3-3h9h) / CVE-2026-48797, and [GHSA-9j7f-3r4p-pwh6](https://github.com/advisories/GHSA-9j7f-3r4p-pwh6).

These items are durable for operators because they repeat common boundaries: MCP transports exposed wider than their intended client, OAuth scopes checked at connection time but not at tool-call time, SAML assertions accepted without cryptographic proof, static/template paths authorized by string prefix rather than containment, HTTP/2 request framing disagreeing with downstream assumptions, and hosting panels applying file operations outside the tenant container.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-rp72-5v5q-2446](https://github.com/advisories/GHSA-rp72-5v5q-2446) | `@cardano402/mcp-server` | missing spending limits, LAN-exposed HTTP transport, and SSRF through `catalog.server.url` | Treat financial or blockchain MCP servers as spend-capable control planes; test transport exposure, per-tool budgets, and URL fetch sinks with owned canaries. |
| [GHSA-73cv-556c-w3g6](https://github.com/advisories/GHSA-73cv-556c-w3g6) / CVE-2026-49257 | `mcp-pinot` | default `oauth_enabled=False` plus `0.0.0.0` bind exposed unauthenticated tool invocation | Add unauthenticated MCP/SSE/HTTP tool enumeration to internal service reviews, especially when default config binds beyond loopback. |
| [GHSA-2r68-g678-7qr3](https://github.com/advisories/GHSA-2r68-g678-7qr3) / CVE-2026-49291 | `mcp-memory-service` | OAuth read-only clients could invoke write/delete memory tools | Test whether protocol scopes are rechecked per tool, not just during session bootstrap. |
| [GHSA-jv46-xfwm-36j7](https://github.com/advisories/GHSA-jv46-xfwm-36j7) / CVE-2026-49454 | Relyra SAML | `SignatureValue` present but not cryptographically verified | Validate SAML integrations with signed canary assertions and negative controls for altered claims/signatures. |
| [GHSA-wpvj-hjcr-h3p2](https://github.com/advisories/GHSA-wpvj-hjcr-h3p2) / CVE-2026-48820 | CakePHP `View::element()` | template element path missed containment checks | Review helper/template loaders where user-controlled element names can cross from approved view directories into sibling paths. |
| [GHSA-3p34-w4f6-5xh2](https://github.com/advisories/GHSA-3p34-w4f6-5xh2) | `better-helperjs` static server | string-prefix traversal in static serving | Reuse static-file sibling-prefix and encoded-separator checks across small dev servers and helper packages, not only full frameworks. |
| [GHSA-pw9p-jvrm-f7rm](https://github.com/advisories/GHSA-pw9p-jvrm-f7rm) / CVE-2026-48979 | PHP standard-library HTTP/2 server path | missing `Content-Length` validation could enable request smuggling | Test HTTP/2-to-origin parser boundaries with single-connection canaries and harmless route effects. |
| [GHSA-rhq6-9rgh-v45c](https://github.com/advisories/GHSA-rhq6-9rgh-v45c) | Pterodactyl Wings | `chmod` operation could affect files outside the server container | Treat panel file APIs as host-boundary surfaces; prove only with disposable canary files and tenant-scoped lab servers. |
| [GHSA-f65r-h4g3-3h9h](https://github.com/advisories/GHSA-f65r-h4g3-3h9h) / CVE-2026-48797 | Backpropagate UI | `backprop ui --auth` and `--share` did not enforce authentication | Verify AI/dev dashboards by route behavior, not by CLI flag names; capture route matrices for unauthenticated access. |
| [GHSA-9j7f-3r4p-pwh6](https://github.com/advisories/GHSA-9j7f-3r4p-pwh6), [GHSA-m8j6-rc5x-wv36](https://github.com/advisories/GHSA-m8j6-rc5x-wv36), [GHSA-72w7-mf9g-733p](https://github.com/advisories/GHSA-72w7-mf9g-733p) | `nono-py` | policy confusion, unknown security fields, and proxy-only fallback bypass | Build policy-decision tables for local sandbox/network tools; include unknown-key, older-kernel, and proxy-fallback negative controls. |

Adjacent advisories for pure denial-of-service, generic account enumeration, log exposure, stored XSS without a stronger operator chain, and parser crashes were reviewed but not promoted into standalone workflows.

## Replayable validation boundaries

### MCP transport and tool-scope harness

- Preconditions: explicit authorization, lab MCP servers, disposable API tokens, no real wallet/provider credentials, and an owned callback endpoint.
- Enumerate MCP transports (`stdio`, SSE, streamable HTTP, plain HTTP) and record bind address, authentication defaults, CORS/origin behavior, and whether browser or LAN clients can reach the server.
- For each exposed tool, compare session-level scope with tool-level authorization: read-only credentials against write/delete/spend tools, unauthenticated requests against list/call routes, and URL-fetch tools against owned callback URLs.
- Evidence should be limited to inert tool calls, synthetic memory rows, fake token values, and owned callbacks. Do not move real funds, read production memories, or target internal services.

### SAML cryptographic-proof harness

- Preconditions: lab IdP/SP pair, disposable users, and permission to test the SAML integration.
- Capture a valid signed assertion for a disposable user, then build negative controls that alter the subject, attributes, audience, and `SignatureValue` while preserving XML shape.
- Positive evidence is an authentication decision matrix showing which altered assertions are accepted or rejected. Do not reuse production assertions, impersonate real users, or bypass customer SSO outside scope.

### Template/static path containment harness

- Preconditions: lab CakePHP/static-server app, synthetic view/static roots, sibling canary files outside the allowed root, and no secrets in the test tree.
- Test path inputs with sibling prefixes (`safe2`), dot segments, encoded separators, mixed slashes, symlinks, and framework-specific template suffixes.
- Capture normalized path, resolved path, HTTP status, and fixed-version negative controls. Do not read `/etc/passwd`, app secrets, real templates, or tenant files.

### HTTP/2 request-boundary harness

- Preconditions: lab server/proxy chain, raw HTTP/2 client tooling, harmless canary routes, and single-user test traffic.
- Send paired requests that vary `Content-Length`, framing, and body presence, then observe whether the front-end and origin disagree about request boundaries.
- Evidence should be single-connection route/cache/auth canaries and byte-level request captures. Do not desynchronize production traffic or target other users.

### Panel file-operation host-boundary harness

- Preconditions: disposable Pterodactyl-like lab node, tenant test server, temp host canary directory, and explicit host-level authorization.
- Exercise only benign metadata/permission operations against in-container paths, symlinks, and path traversal controls that point to disposable canaries outside the tenant root.
- Evidence is before/after mode bits or access decisions for synthetic files. Do not touch real panel configs, server files, credentials, user worlds, or host service paths.

## Reporting notes

- Lead with the crossed boundary: **MCP transport to unauthenticated tool call**, **OAuth scope to write-capable MCP tool**, **SAML signature field to cryptographic verification**, **template/static path to filesystem containment**, **HTTP/2 framing to origin request boundary**, or **panel file operation to host filesystem**.
- Include version, configuration flags, bind address, route/tool matrix, normalized paths, signed/altered assertion decision table, and fixed-version negative controls.
- Keep proofs synthetic and reversible: inert tools, fake tokens, disposable users, harmless canary files, owned callbacks, and lab-only raw HTTP captures.
