---
title: File, tenant, network-config, and redirect authority boundaries
---

# File, tenant, network-config, and redirect authority boundaries

August 7 advisory records expose five reusable operator seams: route decoding after path matching, tenant selectors detached from authenticated identity, structured network configuration serialized into a more powerful grammar, redirect checks applied only to the first peer, and device-control channels that can reach browser-only internal peers.

Sources:

- Postiz local-media traversal: [GHSA-2p7p-3c9x-rwxm / CVE-2026-19264](https://github.com/advisories/GHSA-2p7p-3c9x-rwxm);
- SuperTokens Core tenant separation: [GHSA-j7vw-hh5c-2w6x / CVE-2026-37171](https://github.com/advisories/GHSA-j7vw-hh5c-2w6x);
- libvirt virtual-network XML to dnsmasq configuration injection: [GHSA-f6jp-rhmm-v59g / CVE-2026-61477](https://github.com/advisories/GHSA-f6jp-rhmm-v59g);
- OPeNDAP Hyrax redirect-based SSRF and Earthdata-header forwarding: [GHSA-7c9q-38r9-q62m / CVE-2026-16637](https://github.com/advisories/GHSA-7c9q-38r9-q62m); and
- Telefunken/Vestel SmartCenter `browserseturl` internal-browser reach: [GHSA-7535-6xrw-p7v8 / CVE-2026-15570](https://github.com/advisories/GHSA-7535-6xrw-p7v8); and
- Postiz full-row response echo with secret leakage on delete/member paths: [GHSA-wm8w-ph5r-v9cm / CVE-2026-107761](https://github.com/advisories/GHSA-wm8w-ph5r-v9cm); and
- Postiz unrestricted backend function dispatch with file-read helper: [GHSA-h5r5-h782-vqvp / CVE-2026-115931](https://github.com/advisories/GHSA-h5r5-h782-vqvp).

The GitHub records were unreviewed at scan time. Confirm exact product, version, feature configuration, route or API, principal, and corrected behavior before reporting.

!!! warning "Synthetic objects and denied sinks only"
    Use disposable uploads, two-tenant identities, inert network XML, fake headers, owned no-content redirect peers, and patched file/config/process/network/browser sinks. Never read environment or credential files, forge a session, access another operational tenant, inject executable dnsmasq directives, forward real Earthdata tokens, or probe metadata, loopback, private services, or production devices.

## 1. Preserve the full authority pipeline

For every case record:

```text
principal and feature state
-> raw route, tenant, XML attribute, or URL
-> routing, decoding, parsing, and normalization
-> canonical file/object/config/destination
-> policy decision
-> final denied file, tenant query, config line, process, network peer, or browser sink
```

A response code, parsed value, redirect, or generated path is not sufficient. Require a random synthetic marker at the final recorder and an affected-versus-fixed or explicit negative control.

## 2. Postiz: compare router normalization with handler decoding

The record describes a public local-media route where raw dot segments are collapsed before routing, but encoded separators survive route matching and become traversal only when the handler decodes and joins path segments. The reported downstream JWT and provider-secret impact depends on reading real files and is unnecessary for validation.

1. Run an affected Postiz build with an empty upload root, one public media canary, and one sibling plain-text canary. Remove all real tokens, provider accounts, billing integrations, and user data.
2. Patch the final stream/open call. Capture the raw request target, router parameters, each percent-decode, joined path, lexical normalization, native canonical path, and recorder target.
3. Compare expected media paths, raw dot segments, encoded separators, double encoding, mixed separators, duplicate path/query selectors, nonexistent components, and in-root symlinks to the sibling canary.
4. Exercise unauthenticated, ordinary user, feature-disabled, and fixed-build controls. Stop before opening or returning the sibling file.

A bounded positive is **public route accepts encoded path representation -> handler decoding restores traversal -> denied stream recorder selects the sibling canary**. Do not request process environment, JWT material, database strings, provider secrets, or forge a session. Report file-selector authority only; downstream token impact remains source-reported, not reproduced.

## 2b. October 11 follow-up — Postiz full-row response echo leaks secrets to mutation-only and low-role callers ([GHSA-wm8w-ph5r-v9cm / CVE-2026-107761](https://github.com/advisories/GHSA-wm8w-ph5r-v9cm))

Several Postiz endpoints return the complete database row of the record they operate on instead of only the fields the client needs, and two of them carry secrets the caller is never meant to receive ([GHSA-wm8w-ph5r-v9cm](https://github.com/advisories/GHSA-wm8w-ph5r-v9cm)). Two legs:

1. The public API's **channel delete** returns the deleted integration row, including the channel's platform **access token and refresh token**. A third-party OAuth app permitted only to delete a channel receives that channel's social-platform credentials and can replay them against the connected account **outside Postiz** — the token outlives both the channel and the app's scope grant.
2. `GET /user/organizations` returns each organization row, including its **API key** (admin-only by design), to **every member** of the organization, so a lower-role member calls the public API on behalf of the org.

Both require a valid session/API key/OAuth token and are scoped to the caller's own organization — there is no anonymous or cross-tenant leg. The durable axes generalize beyond this product:

- **Delete is a read in disguise.** Enumerate mutation verbs (delete, archive, restore, transfer) as response-bearing surfaces, not just GET families. A row-echoing delete hands you the secret at the moment the record disappears from every later read.
- **Field-role gating lives per-verb.** A field hidden from one endpoint because it is admin-only still leaks through any sibling verb that serializes the whole row; map each secret-bearing column to *every* route that returns its entity, then compare against the lowest role permitted on that route.
- **OAuth third-party apps are a distinct principal class.** A scoped app token that satisfies the route's permission check but was never intended to receive the echoed fields is a clean bounty-grade path; test whether the leaked token validates directly at the upstream platform, not just inside the app.

Validation stays bounded: disposable org, member role, one fake social-integration row seeded with synthetic canary tokens, and a mock platform endpoint that records token presentation. Never touch real provider accounts or live tokens; a positive is the canary token appearing verbatim in the mutation/list response body of a verb the low-scope principal is permitted to call.

## 2c. October 24 follow-up — Postiz RPC-style channel-function dispatch reaches internal file-read helper; the "token" field becomes the file path ([GHSA-h5r5-h782-vqvp / CVE-2026-115931](https://github.com/advisories/GHSA-h5r5-h782-vqvp), critical)

Postiz lets a signed-in user ask the backend to run a function against one of *their* connected channels — and the backend never restricted **which** functions are dispatchable. Two internal helpers were reachable from the web surface: one reads an arbitrary file from the server's disk, the other makes the process exit from a single request. The file-read leg composes with a second missing control: a channel's **stored token is never format-validated**, so a user connects a "channel" whose token field is a file path, then invokes the read helper to have the backend return that file — including the process environment, which holds the session-signing secret, the database address, and the credentials of every connected service. Self-registration is open by default, so there is no existing-account precondition. ([GHSA-h5r5-h782-vqvp](https://github.com/advisories/GHSA-h5r5-h782-vqvp))

Durable axes for hunters:

- **RPC-style dispatch surfaces need a callable-name allowlist; "it runs against your own resource" is not one.** Any endpoint shaped like `POST /…/{action|function|method}` that fans into backend code paths is a recon target: enumerate dispatchable names from client bundles, route maps, or error strings, then probe each against a helper inventory (read, exec, exit/restart, fetch). A helper "never meant to be reachable from the web interface" is the classic finding when dispatch is dynamic instead of route-bound.
- **Free-form credential fields are plantable file paths / URLs.** Every "connect an integration" form that stores a token/key/secret string without grammar validation is a smuggling channel into whatever code later consumes that field: file path → arbitrary read (this leg), URL → SSRF, command → injection. Before trusting the fetcher's guards, test the *field* with each sink-shaped value and see whether the consumer resolves it. The pairing rule: a read helper + an attacker-controlled path argument = arbitrary read even when each side alone looks harmless — validate target *and* caller separately.
- **Env-file disclosure is the full-deauth chain in one response.** Where the read reaches `.env`/process env, one request hands you the session-signing secret (forge any user, including admins), DB credentials, and third-party tokens. Frame the report around the signing secret, not file-read semantics.
- Same-wave second leg: a single request kills the process — availability-only, but on dispatch surfaces note every lifecycle helper (exit, restart, reload) that is dispatchable; restart races pair with the Oct 23 KEV cover-window pattern.
- Validation boundary: disposable Postiz install, synthetic fake tokens, canary file outside the app root, never the real `.env`; positive = canary bytes in the response. GHSA package version fields were empty at scan time — confirm bands against the vendor advisory before reporting.

## 3. SuperTokens: bind tenant identity at every query and mutation

Treat the sparse SuperTokens record as a hypothesis requiring a two-tenant matrix, not evidence that every endpoint crosses tenants.

1. Create tenants A and B, users A1/B1, sessions SA/SB, and marker-only tenant data. Use no production recipes, users, or tokens.
2. Capture how the SDK, HTTP path, headers, query/body fields, session payload, and database key represent tenant identity.
3. As A1, replay each session, user, recipe, and administrative operation with the explicit tenant selector omitted, set to A, set to B, duplicated, case-changed, or represented through a sibling endpoint/version.
4. Patch query, serializer, update, revoke, and delete sinks. For reads return only a random B marker ID; for writes record the canonical target and perform no mutation.
5. Compare unauthenticated, A1, B1, expected tenant administrator, cross-tenant operator if the product supports one, nonexistent tenant, and corrected builds.

The positive is **A-authenticated context -> caller-selected or defaulted tenant B -> B's canonical object reaches a read/mutation recorder without explicit cross-tenant authority**. A tenant ID in a response, an endpoint accepting the parameter, or shared deployment membership is insufficient. Never return session bodies, password hashes, email addresses, reset material, or real tenant records.

## 4. libvirt: trace XML fields into generated dnsmasq grammar

The libvirt record says newline characters in virtual-network DNS TXT values and SRV domain/target attributes can become additional dnsmasq configuration directives. The required principal must already be allowed to define virtual networks; preserve that precondition and determine whether the deployment treats that role as unprivileged relative to the host.

Use an isolated host with no guest/customer networks. Replace dnsmasq launch with a recorder and use only an inert unknown directive such as a unique comment-like canary; do not name `dhcp-script`, hooks, executables, files, or shell commands.

1. Submit ordinary TXT and SRV values, then newline/control-character-shaped inert markers through every accepted API representation.
2. Capture raw XML, parsed attribute value, validation result, serialized dnsmasq bytes, line/token parse, generated argv/config path, and denied process start.
3. Compare XML entity forms, CR/LF combinations, canonical API versus alternate import/update routes, direct file input versus management API, and fixed libvirt builds.
4. Verify that the principal truly has network-definition permission but not host process authority; do not call this a tenant escape if the same role is intentionally a host administrator.

A bounded positive is **network-definition principal -> one XML attribute -> generated dnsmasq file contains a second inert directive token -> patched dnsmasq launch selects that configuration**. This proves configuration-grammar injection and privileged process reachability, not command execution. Keep parser injection, process launch, and root impact separate.

## 5. OPeNDAP: enforce destination and credential policy per redirect hop

Use two owned no-content peers: A is allowlisted and redirects; B is denied and records only a random request marker plus the **names** of synthetic headers. Seed Hyrax with fake `User-Id` and `Echo-Token` values.

Build a matrix for no redirect, same-authority redirect, host/scheme/port changes, multiple hops, relative `Location`, user-info, trailing dot, case, encoded delimiters, DNS changes, and loops. Capture raw URL, allowlist decision, redirect response, resolved next URL, DNS/final peer tuple, headers before and after each hop, and denied connector call.

A safe positive is **initial peer A passes -> redirect selects owned denied peer B without a new policy decision**, with a separate finding if synthetic credential headers remain attached across the authority change. Never use metadata, loopback, RFC1918/ULA, third-party hosts, real Earthdata credentials, or content-bearing endpoints.

## 6. SmartCenter: distinguish control-channel reach from browser navigation

The device record describes a same-LAN SmartCenter command that can direct the embedded browser to destinations ordinary browser navigation cannot reach. Validate only on an owned isolated television/device or a vendor lab, with one synthetic internal HTTP service that returns an empty canary response.

1. Record control-channel discovery, pairing/authentication state, sender identity, command grammar, URL parser result, and browser dispatch sink.
2. Compare ordinary external owned URL, synthetic denied-service URL, browser-navigation control, command-channel dispatch, malformed schemes, alternate ports, and fixed firmware.
3. Patch browser dispatch when possible; otherwise use only the isolated canary service and record one request marker. Do not target actual loopback services, settings APIs, media, credentials, or other LAN devices.

A bounded positive is **unauthorized or insufficiently scoped LAN principal -> `browserseturl` -> browser dispatcher selects a synthetic service that normal navigation denies**. State the pairing/network precondition and do not generalize one canary request to arbitrary internal-service compromise.

## Reporting checklist

- [ ] Exact affected/fixed product versions and feature prerequisites are recorded.
- [ ] Raw, decoded, normalized, canonical, and final-sink representations are preserved.
- [ ] File content, tenant data, process execution, real credentials, and internal services remain out of scope.
- [ ] Redirect destination policy and credential-forwarding policy are reported separately.
- [ ] The libvirt principal's intended authority is documented before claiming privilege escalation.
- [ ] Every positive has a synthetic final sink plus negative and fixed controls.
