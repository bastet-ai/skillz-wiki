---
title: URL parser, policy-path, tenant-object, and OAuth redirect boundaries
---

# URL parser, policy-path, tenant-object, and OAuth redirect boundaries

A late July 30 advisory wave exposes four reusable operator patterns: an SSRF validator and fetcher can disagree about URL authority; an application-layer policy and backend can normalize paths differently; object IDs can cross tenant or channel scope; and OAuth redirect matching can confuse a hostname suffix with a subdomain boundary.

Sources:

- [dssrf GHSA-cg4g-m8jx-vjv2 / CVE-2026-54722](https://github.com/advisories/GHSA-cg4g-m8jx-vjv2): raw-string `@` removal changes the authority validated by `URL`, while the original URL is fetched;
- [Swarms GHSA-v37m-33r4-9ggf / CVE-2026-67346](https://github.com/advisories/GHSA-v37m-33r4-9ggf): image/audio URL checks do not bind the hostname to its resolved and connected destination;
- [Calico GHSA-gm75-wg2c-p77x / CVE-2026-6540](https://github.com/advisories/GHSA-gm75-wg2c-p77x) and [Tigera TTA-2026-005](https://www.tigera.io/security-bulletins/tta-2026-005): Dikastes prefix rules and downstream HTTP components disagree on path normalization;
- [Julep GHSA-42mr-mcg5-367r / CVE-2026-67348](https://github.com/advisories/GHSA-42mr-mcg5-367r): `get_execution_details` accepts another tenant's execution ID;
- [Vendure GHSA-327h-gp7q-mxcj / CVE-2026-67347](https://github.com/advisories/GHSA-327h-gp7q-mxcj): stock-location and asset updates accept global IDs from another channel; and
- [MaxKey GHSA-7957-wqgw-m3j9 / CVE-2026-67345](https://github.com/advisories/GHSA-7957-wqgw-m3j9): redirect-host suffix matching does not require a DNS label boundary.

!!! warning "Authorized fixtures only"
    Use owned callback domains, local canary HTTP services, synthetic tenant records, disposable OAuth clients, and a lab Calico workload. Never target metadata services, internal production hosts, real agent executions, customer inventory/assets, victim authorization codes, or shared cluster policy.

## One decision matrix

| Boundary | Trusted decision input | Actual sink input | Bounded positive |
| --- | --- | --- | --- |
| SSRF URL | sanitized or initially resolved authority | original URL, redirect destination, or later DNS answer | owned final listener receives the canary |
| HTTP policy | raw path matched by prefix rule | backend-normalized path | permitted wire path reaches denied canary route |
| tenant object | authenticated tenant plus supplied ID | global execution/entity lookup | foreign synthetic marker is read or changed |
| OAuth redirect | suffix-matched hostname | browser's actual redirect authority | code-shaped canary reaches an owned non-client host |

Preserve validation, parsing, DNS, connection, redirect, policy, backend normalization, object lookup, and authorization as separate edges. Do not infer final-destination access from a validator return value or cross-tenant impact from a globally formatted ID.

## Validator-to-fetcher authority differential

1. Put a harmless marker service on an isolated address and an owned public listener on another address. Instrument both; return no credentials or environment data.
2. Pass the same candidate through the exact validator and HTTP client used by the application. Record the raw string, validator-normalized string, parsed username/password/hostname/port, DNS answer set, connected peer, redirect chain, and final listener.
3. Build a corpus around authority grammar rather than one payload: userinfo delimiters, percent-encoded delimiters, bracketed hosts, trailing dots, mixed-case names, multiple DNS answers, redirects, and rebinding between validation and connection.
4. For dssrf, specifically compare the raw URL parsed by the fetcher with the string produced after `@` removal. A positive requires that validation approves one authority while the unchanged fetch input reaches the owned canary authority.
5. For Swarms image/audio loaders, resolve only owned hostnames. Test whether each address is classified, whether the connected address is pinned to the approved result, and whether every redirect is revalidated.
6. Repeat against dssrf 1.0.4 or the relevant corrected Swarms commit with identical fixtures.

Report **validator authority A -> fetcher authority B -> owned final-destination receipt**. Never use cloud metadata or a production internal service as proof.

## Calico policy-to-backend path differential

The affected application-layer policy is disabled by default. First confirm that Dikastes-backed HTTP rules are actually enabled; ordinary Kubernetes NetworkPolicy is not enough.

1. Deploy a disposable workload with `/allowed/canary` and `/denied/canary`; both increment separate no-op counters.
2. Apply a Prefix policy permitting only `/allowed/`. Put a raw-byte recorder before the backend if the lab architecture permits it.
3. Send one path mutation at a time: dot segments, encoded slash forms accepted by the stack, and repeated slashes. Capture the wire target, policy decision, proxy-forwarded target, backend-decoded path, selected route, and counter delta.
4. Use negative controls for a denied canonical path, a permitted canonical path, no policy, a backend that does not normalize the candidate, and corrected Calico builds.
5. A positive is **Dikastes permits the wire path under the allowed prefix -> downstream normalization selects `/denied/canary` -> only the denied counter changes**.

Do not test destructive endpoints. This is a parser differential, not proof that every ingress, service mesh, or backend normalizes identically.

## Tenant and channel object-ID substitution

1. Create tenants/channels A and B, separate low-privilege users, and records containing random markers only.
2. Establish controls: A can access A's execution/asset/stock location; A is denied B's object through intended UI and list routes.
3. From A, substitute B's ID only in Julep execution-detail requests and Vendure asset or stock-location update requests. For Vendure, change a harmless marker field and immediately restore it.
4. Compare read, update, list, and delete independently. Capture actor tenant/channel, route, object owner, supplied ID, status, returned marker label, and before/after hash.
5. Repeat with nonexistent IDs, same-tenant IDs, an administrator, and corrected builds.

Strong evidence is **valid low-privilege session + foreign global ID -> backend object lookup succeeds without binding object scope to actor scope -> synthetic disclosure or mutation**. Do not collect prompts, task outputs, temporal tokens, catalog media, or inventory from real tenants.

## OAuth redirect hostname-boundary checks

1. Register `https://client.example.test/callback` for a disposable MaxKey client and operate a separate suffix-confusion host such as `notclient.example.test` only if both names are owned lab domains.
2. Generate authorization requests that vary exact host, true subdomain, lookalike suffix, port, scheme, path, case, trailing dot, and IDNA form one dimension at a time.
3. Stop before real authorization. Use a synthetic user and a code-shaped marker that the owned listener records but cannot exchange for production access.
4. Record registered URI, supplied URI, parser-derived hostname, match result, browser final authority, and whether the fixed build rejects it.
5. A hostname suffix is acceptable only when the implementation intentionally permits subdomains and verifies `candidate == registered` or `candidate.endsWith("." + registered)` at a canonical DNS-label boundary. Path and port policy remain separate.

Report **registered host suffix comparison -> attacker-owned lookalike host accepted -> synthetic authorization response delivered to that host**. Redact all actual codes and tokens.

## July 30 Kanboard numeric-IPv4 follow-up

[GHSA-rj28-q96f-28vw / CVE-2026-57862](https://github.com/advisories/GHSA-rj28-q96f-28vw) adds a concrete parser differential to this methodology. Kanboard 1.2.52 and earlier reportedly passed a user-controlled web-link URL through `FILTER_VALIDATE_IP`; hexadecimal IPv4 was rejected as an IP literal by that validator and therefore treated as safe, while cURL still resolved it as an address.

1. Use a lab Kanboard user, an owned HTTP canary on an isolated private test address, and no route to production networks or metadata services.
2. Submit the same canary destination as canonical dotted decimal, hexadecimal IPv4, decimal integer, octal-like form, mixed-base form if the exact cURL build accepts it, and an owned hostname. Change one representation at a time.
3. Record raw URL, PHP validator result, parsed hostname, cURL version, DNS use, connected peer, redirect chain, and final canary receipt.
4. Compare direct client behavior, application behavior, a public owned address, malformed numeric forms, and a corrected implementation that converts every accepted representation to a canonical address before policy.
5. A positive is **validator classifies alternate numeric host as non-IP/safe -> cURL connects to the same blocked-class lab address -> owned canary records the request**.

Do not use localhost, RFC1918 production services, cloud metadata, or any internal service as proof.

## Evidence checklist

Preserve exact package/product versions, enabled feature flags, raw and normalized inputs, parser outputs, DNS and connected-peer evidence, route/policy decisions, synthetic ownership tables, and fixed-version differentials. Keep claims narrow: parser disagreement, final-destination reachability, policy bypass, foreign-object access, and redirect delivery are distinct findings.

## October 7 follow-up: Actual Sync Server CORS-proxy GitHub allowlist prefix bypass — same-owner sibling repos read with the server token (CVE-2026-57449 / [GHSA-m62c-5q34-f3cf](https://github.com/advisories/GHSA-m62c-5q34-f3cf), high)

Actual Sync Server's `GET /cors-proxy?url=...` fetcher is confined to an allowlist of official plugin repositories, but the `api.github.com` branch of `isUrlAllowed()` tests `url.pathname.startsWith('/repos/{owner}/{repo}')` **with no path-segment boundary after the repo name** (the generic branch requires `repoUrl + '/'`; the API branch drops it). An allowlisted public repo `acme/plugin` therefore authorizes `/repos/acme/plugin-private/contents/.env`, `/repos/acme/plugin-secrets/actions/secrets`, `/repos/acme/plugin-internal/releases` — and the proxy then attaches the server's `ACTUAL_GITHUB_TOKEN`, so *any authenticated Actual user* reads private same-owner repos through server authority. Classic confused-deputy proxy: the credential belongs to the server, the allowlist belongs to the policy, and the prefix test silently widens one into the other.

Durable axes (extends this page's Calico prefix-rule and MaxKey suffix-boundary legs):

1. **Prefix/suffix allowlists must be tested for a boundary character, per parser branch.** The bug's sharpest tell: the *same function* had a correct `+ '/'` check on one branch and a bare `startsWith` on the API branch. When auditing any allowlist matcher, enumerate its alternation branches separately — a fix/correctness applied to one branch proves nothing about siblings. Probe family: for allowlisted entry `X`, request `X` + `-marker`, `X` + `_marker`, `X%2F`-encoded, and `X/` proper; the `-marker` variant returning 200-with-data while `X/../foreign` returns 403 is the boundary-missing fingerprint.
2. **Target naming-convention clusters, not just the allowlisted object.** Enumerate the allowlist source (here a public `plugins.json`), then enumerate the *same owner's* repo namespace (GitHub search/API, or username-guessing) looking for prefix siblings with secrets-flavored names (`-private`, `-internal`, `-secrets`, `-infra`). The server token's ACL, not the allowlist, defines the true read scope — check what the token can actually see by testing a canary private sibling you control in a lab fork.
3. **Self-hosted sync-server instances are the recon target, not app.hexagon.cn.** Feature-flag fingerprint: the route only exists with `ACTUAL_CORS_PROXY_ENABLED=true`, and GitHub-token behavior shows up as a distinctive `User-Agent` (`Actual-Budget-Plugin-System`) if you control a URL the proxy visits. On authorized engagements, `GET /cors-proxy?url=` reachability + an owned-callback canary proves the proxy is live before testing allowlist shape.
4. Proof discipline: use a disposable org with `canary-plugin` (public, allowlisted in a lab `plugins.json`) + `canary-plugin-private` holding a synthetic marker file; prove the read with the lab token only. Never pull real vendor/customer private-repo contents or production tokens into evidence.

## October 8 06:31Z follow-up: Heimdall's SSRF guard exists but only guards one controller (CVE-2026-107449 / [GHSA-hrj5-rw8j-34qj](https://github.com/advisories/GHSA-hrj5-rw8j-34qj), linuxserver Heimdall ≤2.8.3)

Heimdall ships a `SafeUrlFetcher` with IP-address restrictions — applied **only to `ItemController`**. The enhanced-application **test and live-stats** flows (`POST /test_config`, `GET /get_stats`) fetch through `SupportedApps::execute()`, a plain `GuzzleHttp` client with **no IP restrictions**, reachable (via CSRF) by an unauthenticated attacker → server-side requests to arbitrary internal hosts/ports including `169.254.169.254`, with a status/port oracle plus partial response data.

- Durable axis, sharpened for dashboards/apps with an "app catalogue": **a security control's existence proves nothing about its coverage — map guard-to-caller, not guard existence.** The out-of-band catalog-integration feature (each supported-app template defines its own health/test URL shape) is the classic second fetch path: when a product adds a safe fetcher for the user-facing CRUD, every *other* outbound caller — plugin/app-integration executors, stats pollers, webhooks, update checkers, preview renderers — needs the same guard, and routinely doesn't. Fingerprint rule: on any self-hosted dashboard/monitoring/product-catalog app, enumerate feature-test/live-stats/webhook endpoints (the catalog templates name them) and drive them at loopback and link-local ranges; a status-code/port oracle from an unauthenticated CSRFable route is a finding even without full-body read.
- Same wave tracked without publication: SecuShare Pro unauthenticated OS command injection ([CVE-2026-107459 / GHSA-4jx8-6ccx-h2wp](https://github.com/advisories/GHSA-4jx8-6ccx-h2wp), critical — detail-free single, cmdi canonical), Stump ≤0.1.10 GraphQL smartlist mutation authorization ([GHSA-2w7f-m7xm-pw66](https://github.com/advisories/GHSA-2w7f-m7xm-pw66), missing-authorization canonical), Wallet System for WooCommerce trio / SMS Alert / Track Orders / Appointment Booking trio / Ultimate Multisite / GPTranslate / Final Tiles Grid pair / Frontend Dashboard / EDD block / Database Addon for WPForms / BackWPup capability-drift legs — all missing-ownership/capability/sanitizer canonicals per precedent (BackWPup's topology-dependent legs promoted on the Sept 19 WP alternate-surface page).

## October 8 18:3xZ follow-up: FFmpeg RTSP 3xx redirect escapes `-protocol_whitelist` — the demuxer's redirect hop is a second fetch with the guard left behind (CVE-2026-107698 / [GHSA-jhxg-38qw-fjxv](https://github.com/advisories/GHSA-jhxg-38qw-fjxv), medium, fixed 7.1.4 / 8.0.2)

`ff_rtsp_connect()` follows RTSP `3xx` `Location:` redirects **without validating the target URL against the configured protocol whitelist** — a malicious RTSP server redirects the client to internal hosts and ports *under other schemes*, defeating the one control operators believe constrains media-tool fetches. Durable axes for media-pipeline SSRF:

1. **Guards that consume the input URL are per-request-hop, not per-session.** Same check-vs-connect and validation-on-first-URL-only genealogy as the Crawlee sitemap leg, the 9router prefetch TOCTOU, and the Malcolm FilePond `FOLLOWLOCATION` leg folded the same day: when any fetch path enables redirect following, the whitelist/allowlist/scheme check that ran on URL #1 says nothing about URLs #2..N. Probe battery on every media/preview/crawler fetch surface: owned redirector that 3xx's from an allowed scheme/port to a disallowed scheme (`rtsp:` → `http://169.254.169.254/`, `file:`-class shapes, internal port), then diff whitelist enforcement first-hop vs redirect-hop.
2. **Protocol whitelist is the media-stack equivalent of a scheme allowlist — test the redirect leg first.** Fingerprint: any service that hands a user URL to FFmpeg/avconv (thumbnailers, streaming ingest, forensics viewers, the Malcolm/Arkime ecosystem itself) is reachable to internal ports *through* a hostile upstream media server, no vulnerable codec needed.
3. Proof stays lab-bounded: your own RTSP responder emitting a crafted `3xx`, your own callback listener as the redirect target; never pivot into unowned internal ranges.
