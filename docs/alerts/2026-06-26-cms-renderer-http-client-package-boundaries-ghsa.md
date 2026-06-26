# CMS, renderer, HTTP-client, and package-manager boundary checks

Source: hourly offensive-security scan, 2026-06-26. Primary entries: GitHub Advisory Database [GHSA-2497-6pwj-pwg7](https://github.com/advisories/GHSA-2497-6pwj-pwg7) / CVE-2026-49288, [GHSA-m92m-r54r-x8r2](https://github.com/advisories/GHSA-m92m-r54r-x8r2) / CVE-2026-49287, [GHSA-x8g9-h984-pc36](https://github.com/advisories/GHSA-x8g9-h984-pc36) / CVE-2026-49359, [GHSA-2fmj-p74r-3wjm](https://github.com/advisories/GHSA-2fmj-p74r-3wjm) / CVE-2026-49286, [GHSA-f5gc-qxf8-mh9g](https://github.com/advisories/GHSA-f5gc-qxf8-mh9g) / CVE-2026-49260, [GHSA-f9vr-g2g2-x9fg](https://github.com/advisories/GHSA-f9vr-g2g2-x9fg) / CVE-2026-47072, [GHSA-j9wq-vxxc-94wf](https://github.com/advisories/GHSA-j9wq-vxxc-94wf) / CVE-2026-47075, [GHSA-mp55-p8c9-rfw2](https://github.com/advisories/GHSA-mp55-p8c9-rfw2) / CVE-2026-47069, [GHSA-h73q-4w9q-82h4](https://github.com/advisories/GHSA-h73q-4w9q-82h4) / CVE-2026-47070, [GHSA-pj7v-xfvx-wmjq](https://github.com/advisories/GHSA-pj7v-xfvx-wmjq) / CVE-2026-47076, [GHSA-mmj8-wcvw-6789](https://github.com/advisories/GHSA-mmj8-wcvw-6789) / CVE-2026-49262, [GHSA-hg3w-7f8c-63hp](https://github.com/advisories/GHSA-hg3w-7f8c-63hp) / CVE-2026-48995, [GHSA-jq42-7mfv-hm57](https://github.com/advisories/GHSA-jq42-7mfv-hm57) / CVE-2026-5223, and [GHSA-p688-r7jv-fm6f](https://github.com/advisories/GHSA-p688-r7jv-fm6f) / CVE-2026-5222. Late-hour additions: Statamic [GHSA-7mqq-4v55-88gh](https://github.com/advisories/GHSA-7mqq-4v55-88gh), [GHSA-h77m-qrj7-jxcw](https://github.com/advisories/GHSA-h77m-qrj7-jxcw), [GHSA-v5c4-wcpj-x73m](https://github.com/advisories/GHSA-v5c4-wcpj-x73m); pnpm [GHSA-p4xf-rf54-rj3x](https://github.com/advisories/GHSA-p4xf-rf54-rj3x), [GHSA-rxhj-4m44-96r4](https://github.com/advisories/GHSA-rxhj-4m44-96r4), [GHSA-hwx4-2j3j-g496](https://github.com/advisories/GHSA-hwx4-2j3j-g496), [GHSA-cjhr-43r9-cfmw](https://github.com/advisories/GHSA-cjhr-43r9-cfmw), [GHSA-q6j5-fjx5-2mc3](https://github.com/advisories/GHSA-q6j5-fjx5-2mc3), [GHSA-54hh-g5mx-jqcp](https://github.com/advisories/GHSA-54hh-g5mx-jqcp), [GHSA-3qhv-2rgh-x77r](https://github.com/advisories/GHSA-3qhv-2rgh-x77r); registry/webhook [GHSA-qvqc-4c52-x6qp](https://github.com/advisories/GHSA-qvqc-4c52-x6qp), [GHSA-8jgf-23q5-x7xx](https://github.com/advisories/GHSA-8jgf-23q5-x7xx); and Nezha [GHSA-5c25-7vpj-9mqh](https://github.com/advisories/GHSA-5c25-7vpj-9mqh), [GHSA-x6fg-52vr-hj4w](https://github.com/advisories/GHSA-x6fg-52vr-hj4w), [GHSA-39g2-8x68-pmx8](https://github.com/advisories/GHSA-39g2-8x68-pmx8), [GHSA-9rc6-8cjv-rcvx](https://github.com/advisories/GHSA-9rc6-8cjv-rcvx).

These items are durable for operators because they repeat high-value boundaries: CMS control-panel helpers that disclose restricted resources or invoke unsafe methods, HTML-to-PDF wrappers that translate user-controlled filenames/attachments/binary paths into SSRF, local-file reads, PHAR parsing, or shell command construction, HTTP clients that normalize URLs differently than allowlists or leak credentials across redirects, and package managers that bind lockfiles, registry identity, cache entries, and credentials too loosely.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-2497-6pwj-pwg7](https://github.com/advisories/GHSA-2497-6pwj-pwg7) / CVE-2026-49288 | Statamic CMS | Control Panel fieldtype endpoints missed authorization and disclosed restricted resources | Add fieldtype/widget/helper endpoints to CMS route matrices; compare visible resources across low-privilege users, draft/private objects, and fixed versions. |
| [GHSA-m92m-r54r-x8r2](https://github.com/advisories/GHSA-m92m-r54r-x8r2) / CVE-2026-49287 | Statamic CMS | collection sorting could invoke unsafe methods and destroy data | Treat sort/filter method names as server-side method-dispatch inputs; prove only with disposable collections and no destructive production calls. |
| [GHSA-x8g9-h984-pc36](https://github.com/advisories/GHSA-x8g9-h984-pc36) / CVE-2026-49359 | `pontedilana/php-weasyprint` | attachment option could trigger SSRF and local file disclosure | Review PDF-renderer attachment, asset, stylesheet, and URL options as outbound-fetch and file-read sinks with owned callbacks and synthetic canaries. |
| [GHSA-2fmj-p74r-3wjm](https://github.com/advisories/GHSA-2fmj-p74r-3wjm) / CVE-2026-49286 | `pontedilana/php-weasyprint` | output filename could reach PHAR deserialization through a case-insensitive bypass | Include extension case, stream-wrapper, and archive-wrapper variants in renderer output-path tests, bounded to inert marker files. |
| [GHSA-f5gc-qxf8-mh9g](https://github.com/advisories/GHSA-f5gc-qxf8-mh9g) / CVE-2026-49260 | `pontedilana/php-weasyprint` | configurable WeasyPrint binary path could cross into shell command construction | Check whether renderer binary path/config values are user- or tenant-controlled; prove with inert temp binaries in a disposable lab only. |
| [GHSA-f9vr-g2g2-x9fg](https://github.com/advisories/GHSA-f9vr-g2g2-x9fg), [GHSA-j9wq-vxxc-94wf](https://github.com/advisories/GHSA-j9wq-vxxc-94wf), [GHSA-mp55-p8c9-rfw2](https://github.com/advisories/GHSA-mp55-p8c9-rfw2) | Hackney | CRLF/header injection through WebSocket upgrade, query, cookie `domain`, and cookie `path` inputs | Fuzz string-to-wire boundaries in HTTP clients with raw-capture canaries; focus on injected request headers, not service disruption. |
| [GHSA-h73q-4w9q-82h4](https://github.com/advisories/GHSA-h73q-4w9q-82h4) | Hackney | cross-origin redirect could leak Authorization, Cookie, and request body | Add redirect authority/scheme/port transitions to credential-forwarding tests for API clients and webhook relays. |
| [GHSA-pj7v-xfvx-wmjq](https://github.com/advisories/GHSA-pj7v-xfvx-wmjq) / CVE-2026-47076 | Hackney | percent-encoded host normalization could bypass SSRF allowlists | Exercise URL canonicalization with percent-encoded host bytes, IPv6/IPv4 forms, userinfo, trailing dots, and redirect hops against owned callbacks. |
| [GHSA-mmj8-wcvw-6789](https://github.com/advisories/GHSA-mmj8-wcvw-6789) / CVE-2026-49262 | Aimeos Pagible CMS | admin proxy SSRF via DNS rebinding | Treat admin-side proxy/preview features as SSRF sinks even when the initial URL host passes validation; prove with owned rebinding domains and synthetic internal canaries only. |
| [GHSA-hg3w-7f8c-63hp](https://github.com/advisories/GHSA-hg3w-7f8c-63hp) / CVE-2026-48995 | pnpm | GitHub git-dependency tarball hashes were not stored in the lockfile | Review lockfile reproducibility and git-dependency integrity when testing repository trust and dependency-confusion paths. |
| [GHSA-jq42-7mfv-hm57](https://github.com/advisories/GHSA-jq42-7mfv-hm57) / CVE-2026-5223 | Cargo | third-party registry crates could override cached sources for other crates | Test registry/cache namespace separation with disposable registries and marker crates, not public package names. |
| [GHSA-p688-r7jv-fm6f](https://github.com/advisories/GHSA-p688-r7jv-fm6f) / CVE-2026-5222 | Cargo | credentials could be shared between registries | Include registry credential scope and redirect/alias behavior in supply-chain reviews; use fake tokens and owned registries only. |

Adjacent Hackney availability issues, parser loops, and buffer-exhaustion advisories were reviewed but not promoted as standalone workflows because they did not add non-availability operator value.

## Replayable validation boundaries

### CMS control-panel helper harness

- Preconditions: authorized lab CMS instance, two disposable users with different roles, synthetic private/draft resources, and backups of any test collections.
- Enumerate non-obvious Control Panel endpoints: fieldtype previews, relation pickers, sort/filter helpers, widgets, import/export routes, and AJAX helpers.
- Compare each endpoint across roles and resource states. Capture route, method, resource ID, expected role, actual response, and fixed-version negative controls.
- For unsafe sort/filter/method-dispatch inputs, use disposable collections only and stop at route behavior or synthetic marker effects. Do not destroy production entries, files, users, or collections.

### HTML-to-PDF renderer file/URL/config harness

- Preconditions: local renderer lab, disposable output directory, owned callback domain, synthetic local canary files, and no production secrets in render paths.
- Map every renderer option that can reference a URL, attachment, stylesheet, binary path, temporary path, or output filename.
- Test URL/file inputs with owned callbacks, redirectors, local canary files, stream-wrapper variants, extension case variants, and output filenames that should remain inside the approved directory.
- Evidence should be callback hits, rendered inclusion of synthetic markers, command-line argument captures, and fixed-version denials. Do not read `/etc/passwd`, cloud metadata, app configs, real customer PDFs, or credentials.

### HTTP-client string-to-wire and redirect harness

- Preconditions: disposable client integration, owned capture server, optional mock proxy, and fake credentials.
- Send canary requests through every user-controlled URL/query/header/cookie option and record the raw bytes received by the capture server.
- Vary CRLF, percent-encoded host bytes, userinfo, IPv6 literals, trailing dots, scheme/port changes, and redirect chains. Compare validation-time URL, normalized URL, and wire-level authority.
- Evidence should be raw request captures showing harmless injected headers, credential-retention decisions, or allowlist mismatch. Do not target internal services or forward live Authorization/Cookie values.

### Package-manager registry/cache credential harness

- Preconditions: scratch project, disposable registries or local registry mocks, fake credentials, marker packages/crates, and isolated caches.
- Test whether lockfiles pin git/tarball content, whether cache keys include registry identity, and whether credentials are scoped by exact registry authority.
- Capture lockfile diffs, cache-key/source-path decisions, HTTP Authorization destinations, and patched negative controls.
- Do not publish typosquats to public registries, reuse real developer tokens, poison shared caches, or modify production lockfiles.

## Late-hour updates: Statamic, pnpm, Nezha, SNS, and registry clients

Additional same-day GitHub advisories landed after the first batch. They are worth grouping here because they extend the same operator themes: CMS helper routes, package-manager repository trust, credential forwarding, and monitoring dashboard control-plane boundaries.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-7mqq-4v55-88gh](https://github.com/advisories/GHSA-7mqq-4v55-88gh) / CVE-2026-54244 | Statamic CMS | view-only users could submit Live Preview content reserved for editors | Add preview/render endpoints to CMS role matrices; prove with harmless draft markers and fixed-version negative controls. |
| [GHSA-h77m-qrj7-jxcw](https://github.com/advisories/GHSA-h77m-qrj7-jxcw) / CVE-2026-54243 | Statamic CMS | exported form submissions could preserve spreadsheet formulas | Treat CSV/export features as client-side execution handoff points; evidence should use inert formula canaries in disposable exports only. |
| [GHSA-v5c4-wcpj-x73m](https://github.com/advisories/GHSA-v5c4-wcpj-x73m) / CVE-2026-54242 | Statamic CMS Glide | image transform/asset fetch path could reach SSRF through DNS rebinding | Re-test media proxy and transform URLs with owned rebinding domains and synthetic internal canaries, never real internal services. |
| [GHSA-p4xf-rf54-rj3x](https://github.com/advisories/GHSA-p4xf-rf54-rj3x) / CVE-2026-50014 | pnpm | lockfile `resolution.commit` could become git-fetch argument injection | Include lockfile-controlled git arguments in repository-trust reviews; prove with inert local git wrappers in scratch projects. |
| [GHSA-rxhj-4m44-96r4](https://github.com/advisories/GHSA-rxhj-4m44-96r4) / CVE-2026-50015 | pnpm | malicious patch files could write/delete outside the package root | Add patch-application path traversal checks using temp outside-root marker files, not shell startup files or credentials. |
| [GHSA-hwx4-2j3j-g496](https://github.com/advisories/GHSA-hwx4-2j3j-g496) / CVE-2026-50016 | pnpm | transitive dependency alias paths could replace project paths through symlinks | Test alias and link targets in isolated repos with canary symlinks and verify resolved paths before install-side effects. |
| [GHSA-cjhr-43r9-cfmw](https://github.com/advisories/GHSA-cjhr-43r9-cfmw) / CVE-2026-50017 | pnpm | repository-selected registries could receive unscoped user-level npm credentials | Use fake tokens and owned registries to prove registry authority scoping; never run tests with real developer npm credentials. |
| [GHSA-q6j5-fjx5-2mc3](https://github.com/advisories/GHSA-q6j5-fjx5-2mc3) / CVE-2026-50021 and [GHSA-54hh-g5mx-jqcp](https://github.com/advisories/GHSA-54hh-g5mx-jqcp) / CVE-2026-50573 | pnpm | missing or unsafe lockfile integrity behavior could allow dependency substitution | Record lockfile integrity fields, fetched artifact digests, and patched refusals with marker packages in scratch registries. |
| [GHSA-3qhv-2rgh-x77r](https://github.com/advisories/GHSA-3qhv-2rgh-x77r) / CVE-2026-55180 | pnpm | repository config could expand victim environment variables into registry requests before scripts run | Treat package-manager config parsing as a secret egress sink even when lifecycle scripts are disabled; prove only with fake environment markers. |
| [GHSA-qvqc-4c52-x6qp](https://github.com/advisories/GHSA-qvqc-4c52-x6qp) / CVE-2026-49349 | `regclient` | external blob-store redirects could receive registry authentication material | Add blob-store redirect authorities to container registry credential-forwarding tests with fake tokens and owned endpoints. |
| [GHSA-8jgf-23q5-x7xx](https://github.com/advisories/GHSA-8jgf-23q5-x7xx) | `ex_aws_sns` | attacker-controlled `SigningCertURL` could be trusted during SNS signature validation | For webhook validators, compare accepted signing certificate hosts, certificate chains, message bodies, and fixed-version denials with locally generated lab certs only. |
| [GHSA-5c25-7vpj-9mqh](https://github.com/advisories/GHSA-5c25-7vpj-9mqh) / CVE-2026-53519 | Nezha Monitoring | `/dashboard..`-style prefix confusion could expose dashboard secret material before auth | Add raw-path and normalized-path prefix confusion to monitoring dashboard route matrices; evidence should be marker-file or route-state proof in a lab. |
| [GHSA-x6fg-52vr-hj4w](https://github.com/advisories/GHSA-x6fg-52vr-hj4w) / CVE-2026-53520 | Nezha Monitoring | authenticated NAT host claims could preempt dashboard routing for a chosen Host | Test Host/routing ownership with disposable users and harmless host canaries; do not hijack production dashboard domains. |
| [GHSA-39g2-8x68-pmx8](https://github.com/advisories/GHSA-39g2-8x68-pmx8) / CVE-2026-53521 | Nezha Monitoring | stored future DDNS profile IDs could reuse another user's DDNS context | Include future-grant/profile-ID reuse in two-user control-plane tests with fake DDNS targets. |
| [GHSA-9rc6-8cjv-rcvx](https://github.com/advisories/GHSA-9rc6-8cjv-rcvx) / CVE-2026-53523 | Nezha Monitoring | OAuth2 redirect URL generation trusted attacker-controlled Host material | Add Host-derived OAuth redirect generation to open-redirect and account-linking checks using owned callback URLs. |

### Package-manager repository-trust addendum

- Preconditions: scratch project, isolated package-manager home/cache, fake npm credentials, owned registry or local capture server, and disposable outside-root marker paths.
- Exercise repository-controlled config, lockfile git dependencies, patch files, aliases, integrity fields, and registry URLs before and after lifecycle-script execution would normally begin.
- Evidence should be outbound fake-token destinations, lockfile/digest mismatches, resolved symlink paths, inert git-wrapper arguments, or marker-file path decisions. Do not run untrusted package scripts, use real npm tokens, or write outside a temp lab root.

### Monitoring dashboard route/identity addendum

- Preconditions: lab Nezha-style monitoring instance, two disposable users, fake DDNS/OAuth endpoints, controlled Host headers, and synthetic dashboard secrets or marker config.
- Compare raw route, normalized route, router match, auth decision, Host-derived URL generation, profile ownership, and patched negative controls.
- Evidence should be route matrices, harmless callback hits, and synthetic marker exposure only. Do not collect real JWT signing keys, production dashboard tokens, DDNS credentials, or tenant telemetry.

### Webhook signature and registry-redirect addendum

- Preconditions: lab webhook validator, locally generated test certificates, fake SNS-style messages, owned registry/blob endpoints, and fake Authorization values.
- For webhook validators, vary certificate URL host, scheme, path, chain, and message body while recording which trust root and payload were accepted.
- For registry clients, force blob-store redirects across authority, scheme, and port boundaries and record whether fake credentials follow.
- Evidence should be acceptance/denial decision tables and raw request captures with fake tokens only.

## Reporting notes

- Lead with the crossed boundary: **fieldtype endpoint to restricted CMS resource**, **renderer attachment to SSRF/local file**, **renderer output path to PHAR/config execution**, **HTTP-client input to wire-level header/authority**, **registry identity to cache/credential scope**, **repository config to secret egress**, **dashboard route/Host to control-plane identity**, or **webhook certificate URL to signature trust**.
- Include exact package/version, route or option name, role matrix, raw request capture, normalized path/URL, callback evidence, fake-token destination, and fixed-version negative control.
- Keep proofs synthetic and reversible: disposable users, owned callbacks, fake tokens, scratch registries, inert binaries, lab certificates, and marker files only.
