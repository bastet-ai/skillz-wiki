---
title: Workflow SSRF, CI evaluator, unpack, TLS, and redirect boundaries from July 28 GHSA updates
---

# Workflow SSRF, CI evaluator, unpack, TLS, and redirect boundaries from July 28 GHSA updates

A July 28 GitHub-reviewed advisory wave and a late July 29 client-library update yield six durable operator checks: special-use IP ranges omitted from an outbound-request guard, untrusted source evaluated by a CI lint rule, overlapping traversal characters surviving bundle unpack sanitization, inverted TLS-hostname policy, a bootstrap server redirecting an automation client to a second authority, and a secure-to-insecure redirect retaining credentials. Each workflow below stops at a synthetic marker and separates parser or policy behavior from the later network, filesystem, or execution effect.

Sources:

- [GHSA-vg6v-j97m-h5xq: Novu CGNAT-range SSRF guard gap](https://github.com/novuhq/novu/security/advisories/GHSA-vg6v-j97m-h5xq)
- [GHSA-3pwp-g2mj-5p3v / CVE-2026-45293: WordPressCS scan-time evaluation](https://github.com/WordPress/WordPress-Coding-Standards/security/advisories/GHSA-3pwp-g2mj-5p3v)
- [WordPressCS fix](https://github.com/WordPress/WordPress-Coding-Standards/commit/a29048d0bbef5cf25d42349c74e4072d3cbc8325)
- [GHSA-7wpj-vvmv-pgm8 / CVE-2026-54545: Wakaru bundle-unpack write](https://github.com/pionxzh/wakaru/security/advisories/GHSA-7wpj-vvmv-pgm8)
- [Wakaru canonical-path fix](https://github.com/pionxzh/wakaru/commit/1d30383b20a6f768786b8ada2f1b0945de13c316)
- [GHSA-4pj9-g833-qx53 / CVE-2026-46428: lettre Boring TLS hostname verification](https://github.com/lettre/lettre/security/advisories/GHSA-4pj9-g833-qx53)
- [lettre hostname-verification fix](https://github.com/lettre/lettre/commit/f5efffc88360dbdbfcef80f465e42d5bce68ca35)
- [GHSA-28f5-38xr-jh2w / CVE-2026-43910: Appium Java client `directConnect` authority change](https://github.com/appium/java-client/security/advisories/GHSA-28f5-38xr-jh2w)
- [Appium Java client fix](https://github.com/appium/java-client/commit/2b9cd442b9dbf56ccc6f1e83aeeb411c0ec230c9)
- [GHSA-pfc9-2cqg-9wq6 / CVE-2026-41715: Reactor Netty HTTP client protocol-downgrade credential forwarding](https://github.com/advisories/GHSA-pfc9-2cqg-9wq6)
- [Reactor Netty redirect-header fix](https://github.com/reactor/reactor-netty/commit/e7ef551eead84ba465324531683fafa03ab96ee9)

The reviewed package ranges are Novu `<3.17.0`, WordPressCS `>=0.14.1,<3.4.1`, `@wakaru/cli >=1.0.0,<1.4.0`, lettre `>=0.10.1,<0.11.22`, and Appium Java client `>=8.2.1,<=10.1.0`. The Reactor advisory lists 1.0.0-1.0.51, 1.1.0-1.1.35, 1.2.0-1.2.17, and 1.3.0-1.3.5. Confirm the exact package, feature, configuration, call path, and fixed-build behavior before reporting.

!!! warning "Authorized validation only"
    Use isolated workers, local listeners, disposable repositories and output roots, synthetic source files, generated test certificates, fake SMTP/HTTP credentials, and mock Appium servers. Never query cloud metadata or internal production services, execute a command from untrusted source, overwrite shell or application files, intercept real credentials or content, or redirect a production automation session.

## Boundary matrix

| Surface | Trusted decision | Attacker-controlled input | Safe proof |
| --- | --- | --- | --- |
| Novu workflow HTTP step or webhook condition | destination is globally reachable | URL or DNS answer in `100.64.0.0/10` | owned listener on a disposable CGNAT lab subnet |
| WordPressCS scan | source is parsed, not executed | `$ver` expression reconstructed by a sniff | instrumented no-op evaluator counter |
| Wakaru unpack | every module remains under output root | overlapping traversal characters in module filename | text marker in a temporary sibling directory |
| lettre with `boring-tls` | certificate name matches SMTP authority | chain-valid certificate for a different lab name | local CA and mock SMTP handshake result |
| Appium Java client | session traffic remains at approved authority | `directConnect*` values in `NEW_SESSION` | second owned HTTPS listener receives marker command |
| Reactor Netty HTTP client | sensitive headers remain bound to a secure transport | HTTPS response redirects to HTTP with redirect following enabled | owned HTTP listener receives a fake credential header |

Capture the first representation, the check result, the canonical destination, and the final effect separately. An accepted URL, parsed bundle, successful lint run, TLS handshake, or session creation is not enough unless the intended harmless sink is reached.

## Novu: special-use ranges are part of SSRF canonicalization

GHSA-vg6v-j97m-h5xq describes a shared `validateUrlSsrf()` denylist that resolves hostnames but omits `100.64.0.0/10`. The affected workflow HTTP request step and webhook filter condition then perform the outbound request. The reusable bug-hunting pattern is **preflight DNS validation recognizes only familiar private ranges while the deployment routes other non-global ranges internally**.

### CGNAT-only callback fixture

1. Run the affected Novu worker in a disposable network namespace or container network with no route to production, cloud metadata, corporate VPNs, or tenant services.
2. Place an owned HTTP listener at one lab address in `100.64.0.0/10`; return only a random marker and log method, path, source address, and marker hash.
3. Add controls on a public test address, loopback, RFC1918, link-local, and the CGNAT listener. Use only addresses owned by the fixture.
4. Exercise both reachable call sites separately: one workflow HTTP step and one webhook filter condition. Record URL parsing, DNS answers, validation verdict, and actual connected peer.
5. Test a literal address and an owned hostname resolving to the same address. If the client resolves again at connection time, add a controlled two-answer DNS fixture to check validation/connection binding without targeting any third-party host.
6. Repeat on `3.17.0` or later and confirm the request is rejected before the listener receives traffic.

A bounded positive result is **owned hostname resolves to a fixture address in `100.64.0.0/10` -> preflight allows it -> Novu worker reaches the owned listener**. Do not request `100.100.100.200`, `169.254.169.254`, or any real internal service. The canary proves the routing-policy gap without collecting metadata.

Generalize the matrix to IPv4-mapped IPv6 and other special-use ranges only in a local classifier harness. Require parser-based CIDR classification and actual-peer evidence; a regex mismatch alone establishes suspect policy, not product-level SSRF reachability.

## WordPressCS: a scanner must not evaluate the source it reviews

GHSA-3pwp-g2mj-5p3v says the `WordPress.WP.EnqueuedResourceParameters` sniff reconstructed the `$ver` argument to enqueue/register functions and passed it to `eval()` while deciding whether it was falsy. This affects the `WordPress` and `WordPress-Extra` rulesets, not `WordPress-Core` or `WordPress-Docs`. The key precondition is that an affected PHPCS ruleset scans attacker-controlled PHP, commonly a pull request or third-party review checkout.

### No-command lint harness

1. Create a disposable repository with an affected WordPressCS version and pin the exact PHPCS standard used by the target pipeline.
2. Confirm with `phpcs -e` that `WordPress.WP.EnqueuedResourceParameters` is active. Save the ruleset and package lock hash.
3. Run a benign enqueue call as the baseline and capture the sniff result.
4. In an instrumented copy of the affected sniff, replace the evaluator's execution primitive with a test double that increments an in-memory counter and returns a fixed value. Do not place shell, filesystem, network, or language-execution payloads in source.
5. Supply a synthetic `$ver` expression that causes the parser to reach the test double. Record the reconstructed expression, call count, and scan context.
6. Add controls using a literal version, a normal variable, the unaffected rulesets, the affected ruleset with this sniff excluded, and WordPressCS `3.4.1` or later.
7. If CI reachability matters, run the marker-only harness in a secretless fork/PR fixture with no deploy credentials, writable package cache, cloud identity, or privileged runner mounts.

Strong evidence is **untrusted PHP enters the configured ruleset -> affected sniff reconstructs it as an evaluable expression -> instrumented evaluator is invoked**, followed by rejection or non-evaluation on `3.4.1`. Do not publish or run a command-execution string; execution capability follows from the proven evaluator edge and the primary advisory.

## Wakaru: sanitize once, then enforce canonical containment

GHSA-7wpj-vvmv-pgm8 describes bundle-controlled module names containing overlapping traversal characters such as `....//`. A single replacement could turn that value into `../`, allowing `wakaru --unpack` to write outside the selected output directory.

### Temporary sibling-root fixture

1. Create `root/out/` and `root/outside/` under one disposable temporary directory. Seed `outside/` with a uniquely named text marker and record its hash.
2. Construct the smallest synthetic JavaScript bundle whose module name exercises the overlapping-character transformation. Include only harmless module text.
3. Run the affected `@wakaru/cli` with `--unpack root/out` as an unprivileged user in a container with only `root/` writable.
4. Record the raw module name, post-sanitization name, joined path, canonical parent, files created, and marker hashes.
5. Add absolute-path, normal nested-path, simple `../`, mixed-separator, duplicate-separator, and sibling-prefix controls. Do not address files outside the temporary root.
6. Repeat on `1.4.0`. Require rejection or confinement before any sibling marker appears.

The decisive result is **bundle-controlled name -> sanitizer creates traversal -> canonical write lands in the disposable sibling directory**. A suspicious transformed string without a file effect is incomplete; a text write does not by itself prove later code execution.

## lettre: verify hostname semantics at the selected TLS backend

GHSA-4pj9-g833-qx53 describes an inverted boolean in lettre's `boring-tls` integration: the strict default `accept_invalid_hostnames=false` was passed directly to a Boring API whose flag means `verify_hostname`. The `native-tls` and `rustls` backends are not affected.

### Local certificate decision table

1. Build lettre with only the `boring-tls` feature and default-strict `TlsParameters`. Record crate version, enabled features, authority, and sync/async path.
2. Generate a disposable local CA and certificates for `smtp-a.test` and `smtp-b.test`. Trust only that CA inside the fixture.
3. Map both names to an owned mock SMTP server. Present the matching certificate, wrong-name but chain-valid certificate, untrusted certificate, expired certificate, and malformed chain in separate runs.
4. Use fake SMTP credentials and a message containing only a random marker. Stop after authenticated submission to the mock; do not relay mail.
5. Repeat with `accept_invalid_hostnames` true and false, sync and async clients, and the unaffected backends as controls.
6. Repeat on `0.11.22`; the strict default must reject the wrong-name certificate while accepting the matching one.

Evidence should show **strict caller configuration + Boring backend + chain-valid wrong-name certificate -> handshake or submission succeeds on the affected version -> fixed version rejects it**. Do not infer a network-position capability from the library bug; report interception impact only where the assessment establishes an attacker-controlled network or SMTP endpoint.

## Appium: bind direct-connect redirects to an approved authority

GHSA-28f5-38xr-jh2w says the Java client with `directConnect(true)` accepted `directConnectHost`, `directConnectPort`, and `directConnectPath` from the `NEW_SESSION` response, then changed the destination for subsequent session commands. Protocol validation alone did not bind that second authority to the approved bootstrap server.

### Two-listener automation fixture

1. Run an owned HTTPS bootstrap server A and second owned HTTPS listener B on an isolated loopback/container network. Use fake session IDs and no devices, emulators, grids, credentials, or cloud endpoints.
2. Configure the affected Java client with `directConnect(true)` and connect only to A.
3. Have A return a synthetic `NEW_SESSION` response whose `directConnect*` fields select B. At B, accept one harmless status/source-shaped request and return a fixed marker.
4. Record the original authority, response fields, normalized second URL, certificate decision, method/path, and listener hit. Redact authorization headers even when fake.
5. Vary same host/different port, different host/same port, path-only changes, loopback, private fixture address, malformed host, and `directConnect(false)`. Never use metadata or internal production addresses.
6. Repeat with Java client `10.1.1`; confirm an unapproved authority is rejected or remains bound to the approved server.

A bounded positive result is **client trusts A -> A supplies authority B -> a post-session command reaches owned B without caller approval**. This proves a server-to-client network pivot primitive. Claims about credential disclosure, internal-service access, or command impact require separate evidence and are unnecessary for this validation.

## Reactor Netty: scheme is part of redirect authority

GHSA-pfc9-2cqg-9wq6 requires explicit redirect following. The one-line fix shows the important differential: sensitive headers were already stripped when the normalized destination URI changed, but the same URI identity could still move from a secure to an insecure transport. The fixed condition independently checks `fromURI.isSecure()` and `toURI.isSecure()` before retaining redirect headers.

### Two-transport credential canary

1. Run an owned HTTPS server A and plain-HTTP recorder B on loopback or an isolated container network. Use a generated lab CA and a fake authorization/cookie marker that has no value outside the fixture.
2. Configure the affected Reactor Netty client to follow redirects. Send the fake credential only to A, then have A return one redirect to B.
3. Record the original and redirected schemes, normalized host/port/path, redirect status, request headers at both listeners, and whether the client reused a connection or created a new one.
4. Test one variable at a time: HTTPS-to-HTTPS same authority, HTTPS-to-HTTP same host/port representation, HTTPS-to-HTTP different port, HTTPS-to-HTTP different host, HTTP-to-HTTPS, and redirect following disabled.
5. Repeat on 1.2.18, 1.3.6, or the corresponding fixed maintenance line. The redirected request may proceed according to caller policy, but credentials, cookies, and other sensitive redirect headers must not cross the secure-to-insecure transition.

Strong evidence is **fake credential sent to owned HTTPS A -> followed downgrade redirect -> owned HTTP B receives that credential on the affected version -> fixed version strips it**. A redirect response alone is not disclosure, and this test does not establish an attacker-controlled redirect source in a real application.

## August 31 follow-up: aiosmtplib STARTTLS plaintext-buffer response injection

[GHSA-vxj7-4xrp-5vr4 / CVE-2026-55558](https://github.com/advisories/GHSA-vxj7-4xrp-5vr4) (aiosmtplib `<=5.1.1`) describes a plaintext-to-TLS buffer carryover: on `start_tls=True`/`None`, the client reads the server's `220` go-ahead and immediately performs the TLS handshake without discarding data still buffered on the plaintext socket. The asyncio transport is swapped in place, so the protocol object and its receive buffer survive the plaintext-to-TLS boundary and are parsed as though they arrived inside the TLS session. An on-path attacker can, in a single segment right after the client's `STARTTLS`, send the `220` reply followed by attacker-chosen response lines (for example `220 Go ahead`, `250-mx.evil`, `250 AUTH LOGIN`); the client consumes only the `220`, leaves the injected lines buffered, completes the handshake, and then parses the pre-staged plaintext as the first post-TLS server response. This also desynchronizes every subsequent command/response pair in the "encrypted" session. Implicit/direct TLS (`use_tls=True`) has no plaintext phase and is not affected.

The durable pattern generalizes to every protocol that upgrades plaintext to TLS in place: **bytes observed on the plaintext leg must be discarded, not replayed, and no security decision may be derived from the plaintext leg after the upgrade.** RFC 3207 section 4.2 requires the client to discard any knowledge obtained from the server before the TLS negotiation; the 5.1.2 fix treats any data buffered after the `220` and before the handshake as a protocol violation.

### STARTTLS boundary fixture

1. Run an owned SMTP server that advertises `STARTTLS` in a lab network namespace, plus a second owned listener behind it that records the first post-upgrade response line and any subsequent command/response pairs. Use fake credentials and a marker EHLO/MAIL payload only; do not relay mail.
2. Connect with the affected aiosmtplib using `start_tls=True` against the owned server. As the control baseline, send only the legitimate `220` after `STARTTLS` and confirm the handshake and subsequent commands are in sync.
3. Mutate: in the same segment after the client's `STARTTLS`, send `220 Go ahead` plus attacker-chosen lines (`250` capability lines naming an owned `.invalid` domain, a fake `AUTH` line). Record which lines the client parses as post-TLS server responses and whether later commands desynchronize (mismatched response codes, duplicate `EHLO`, or command interpreted as data).
4. Add controls: `use_tls=True` implicit TLS (no plaintext phase, must be inert), `start_tls=False`, and aiosmtplib 5.1.2 or later (must reject the buffered post-`220` data as a protocol violation).
5. Repeat with a second owned listener that presents a generated test certificate so the TLS leg is terminated locally; never intercept or terminate production mail traffic.

A bounded positive result is **plaintext buffer carries the injected lines across the STARTTLS boundary -> the client parses attacker-staged lines as the first post-TLS response -> subsequent session commands desynchronize** on the affected version, with 5.1.2 discarding the buffered data. Do not use real mailboxes, real credentials, or third-party SMTP endpoints.

## Reporting checklist

Include:

- exact package/version, feature flags, deployment mode, caller role, and vulnerable call path;
- raw and canonical URL/path/authority, DNS answers, actual connected peer, or final filesystem path;
- ruleset and sniff reachability, reconstructed source expression, and no-op evaluator evidence;
- TLS backend, boolean settings, test certificate SAN/issuer, sync/async path, and handshake result;
- redirect-follow setting, scheme/authority transition, and header-presence diff using fake credentials;
- baseline, one-variable mutations, unaffected-feature controls, and fixed-version results;
- hashes of synthetic markers and proof that all listeners, roots, certificates, credentials, and sessions were disposable;
- a narrow claim separating validation bypass, evaluator reachability, outside-root write, hostname-check failure, and authority redirect from any untested downstream impact.

Never include real tokens, SMTP credentials, message contents, internal hostnames, metadata responses, runner secrets, or files outside the temporary fixture.
## October 1 follow-up: ansible-runner worker-side archive unpack (12:31Z wave, folded)

[CVE-2026-103754 / GHSA-3h4x-374r-8hhc](https://github.com/advisories/GHSA-3h4x-374r-8hhc) (medium): ansible-runner's `unstream_dir()` — the **worker side** of the transmit/worker protocol — re-creates symlinks from streamed zip content **without validating link targets** and applies `chmod()`/`utime()` to paths derived unsanitized from archive member names → file creation, symlink creation, and permission changes outside the target directory, reachable by anyone who can influence the archive a worker consumes. Same invariant as this page's bundle-unpack leg, new transport: the "archive" is not an uploaded artifact but a **protocol stream inside an automation control channel**, and the second sink (chmod/utime on a `..`-shaped member name) is separate from the symlink sink — test link-target escape, member-name traversal, and metadata-apply-on-traversal as three canaries even when file-content writes are contained. Operator angle: for any controller↔worker protocol that ships project trees (ansible-runner, CI runners, agent executors), ask who can get bytes into the stream (repo write access = archive write access) and whether the extraction library's safe mode is actually enabled on the receiving side. Lab-only proofs: temp target root, marker symlink pointing at a denied canary file, `stat` before/after on a traversal-shaped member; never point link targets at real paths.
