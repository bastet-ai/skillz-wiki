# Symfony mail, auth, cache, XML, and log-listener boundary batch (GHSA, 2026-05-27)

**Signal:** A follow-on Symfony advisory batch published after the prior May 27 sanitizer/body/TLS/SQL-agent batch adds multiple replayable offensive-validation boundaries: unauthenticated development log deserialization, method-scoped auth skips, CAS/OIDC identity validation drift, cache-prefix SQL injection, XML local-file disclosure, and mail header / SMTP command injection.

Promoted items:

- `GHSA-m7v2-7gxm-vc2v` / `CVE-2026-45077`: `Symfony\Bridge\Monolog\Command\ServerLogCommand` binds `server:log` to `0.0.0.0:9911` by default and runs unauthenticated `unserialize(base64_decode(...))` on received frames.
- `GHSA-6439-2f28-8p8q` / `CVE-2026-45075`: `#[IsGranted]`, `#[IsSignatureValid]`, and `#[IsCsrfTokenValid]` method filters can skip checks for `HEAD` while the router still executes the `GET` handler.
- `GHSA-j8gj-9rm5-4xhx` / `CVE-2026-45074`: `Cas2Handler` derives its CAS `service` URL from attacker-controlled `Host` when `trusted_hosts` is not configured, enabling cross-service ticket replay.
- `GHSA-29fc-p6c4-24cg` / `CVE-2026-45069`: `OidcTokenHandler` validates `aud`, `iss`, and `exp` only when those claims are present, allowing signed JWTs missing mandatory claims.
- `GHSA-6qh9-h6wf-jgqc` / `CVE-2026-45073`: `PdoAdapter::clear($prefix)` can interpolate caller-influenced cache prefixes into a `LIKE` SQL statement in the non-versioning code path.
- `GHSA-x6g4-fwcc-jj8w` / `CVE-2026-45071`: `DomCrawler::addXmlContent()` enables DTD processing through `validateOnParse`; `LIBXML_NONET` blocks network fetches but not `file://` entity expansion.
- `GHSA-qpmx-3rfj-7rhv` / `CVE-2026-45067`, `GHSA-vqc8-7275-q272` / `CVE-2026-45070`, and `GHSA-xx3c-qf5g-hc39` / `CVE-2026-45068`: Symfony mail address, parameter-name, and sendmail-recipient handling expose CRLF header / SMTP command injection and dash-prefixed sendmail argument injection primitives when applications route untrusted address or parameter slots into mail generation.

Use this only in authorized testing. Keep proofs harmless: demonstrate boundary failure with canaries, local labs, or program-provided fixtures; do not send real emails, replay real authentication tickets, disclose local files, or trigger gadget-chain RCE on production systems without explicit authorization.

## Operator checklist

### 1. Exposed `server:log` deserialization

Where to look:

- Symfony applications, developer boxes, CI runners, containers, or staging hosts where `php bin/console server:log` may be running.
- TCP `9911` reachable beyond loopback, especially on internal networks, preview environments, or port-forwarded dev stacks.
- Versions of `symfony/monolog-bridge` or `symfony/symfony` before `5.4.52`, `6.4.40`, `7.4.12`, or `8.0.12`.

Safe validation path:

1. Confirm the port is open and that the service behaves like the Symfony log listener before sending anything serialized.
2. In a local lab, replay the advisory shape: base64-encoded PHP serialization accepted by the listener.
3. For real targets, prefer a benign type-confusion crash proof only when the program allows service-disruption tests; otherwise report exposed unauthenticated `server:log` plus vulnerable version/configuration.
4. Do not attempt gadget-chain execution on production hosts. If RCE impact matters, reproduce with the target's dependency set in an isolated clone or container.

Reporting heuristic: strong reports show **off-loopback reachability plus unsafe object deserialization in a development log listener**. Include port exposure, command/config evidence, Symfony package versions, and whether the listener is reachable from tenant, VPN, or internet scope.

### 2. Symfony method-scoped attribute bypass with `HEAD`

Where to look:

- Controllers using `#[IsGranted(..., methods: ['GET'])]`, `#[IsSignatureValid(methods: ['GET'])]`, or `#[IsCsrfTokenValid(..., methods: ['GET'])]` on Symfony `7.4.0-7.4.11` or `8.0.0-8.0.11`.
- GET routes whose handlers create side effects, emit sensitive headers, redirects, signed URLs, counters, exports, or cache-warming work.
- Routes where authorization is enforced only by the attribute rather than a broader firewall/access-control rule.

Safe validation path:

1. Identify a protected GET route where an unauthorized `GET` receives a denial.
2. Replay as `HEAD` with the same cookies/headers omitted or downgraded.
3. Compare status, headers, `Location`, `Content-Length`, custom headers, and any observable side effect.
4. Do not rely on missing body content as a non-impact finding; the key is handler execution or header/state leakage.

Reporting heuristic: emphasize **auth/signature/CSRF check skipped while GET handler still runs**. Show GET denied vs HEAD allowed and document any header leak or side effect.

### 3. CAS and OIDC identity validation drift

Where to look:

- Symfony CAS2 integrations using `symfony/security-http` `7.1.0-7.4.11` or `8.0.0-8.0.11`, especially with default / absent `framework.trusted_hosts`.
- Environments sharing a CAS server across multiple apps, tenants, staging hosts, or vanity domains.
- OIDC resource servers using `OidcTokenHandler` in `symfony/security-http` `6.3.0-6.4.39`, `7.4.0-7.4.11`, or `8.0.0-8.0.11`.

Safe validation path:

1. For CAS, first prove `Host` header influence on generated service URLs in a non-sensitive flow or lab. Only attempt cross-service ticket replay with test accounts and explicit authorization from both services.
2. For OIDC, generate a signed test JWT in a lab or program-provided tenant that omits `aud`, `iss`, or `exp`, then confirm whether the handler accepts it.
3. Capture framework version, auth component version, trusted-host configuration, and token/ticket validation logs when available.

Reporting heuristic: high-value reports tie the auth bypass to **real trust-boundary confusion**: a ticket or token accepted for the wrong service, missing audience/issuer/expiry enforcement, or a host-header-influenced identity decision.

### 4. Cache-prefix SQL injection boundary

Where to look:

- `symfony/cache` `PdoAdapter` before `5.4.52`, `6.4.40`, `7.4.12`, or `8.0.12`.
- Admin panels, tenant cache-purge endpoints, preview rebuilders, queue jobs, or internal APIs that let users influence a cache prefix, namespace, tag-like value, or purge key.
- Non-versioning PDO cache configurations where `clear($prefix)` reaches `PdoAdapter::doClear()`.

Safe validation path:

1. Confirm caller influence over the `clear($prefix)` argument rather than just ordinary cache keys.
2. Use a disposable database or staging environment to demonstrate prefix breakout with harmless rows.
3. In production bounty scope, avoid destructive `DELETE` proofs. Prefer source/config evidence plus a staging/lab reproduction using the same vulnerable call path.

Reporting heuristic: the issue is strongest when an untrusted actor can turn **prefix-limited cache clearing into arbitrary SQL semantics or broad deletion**. Document the call path and whether the database user has privileges beyond the cache table.

### 5. XML local-file entity expansion through DomCrawler

Where to look:

- Applications, test harnesses, importers, crawlers, or security tools that pass attacker-supplied XML to `Crawler::addXmlContent()` or BrowserKit/DomCrawler parsing paths.
- Versions of `symfony/dom-crawler` or `symfony/symfony` before `5.4.52`, `6.4.40`, `7.4.12`, or `8.0.12`.
- Server-side XML preview, validation, webhook replay, feed ingestion, document conversion, or crawler features.

Safe validation path:

1. Reproduce locally first with a harmless `file://` target you create, not `/etc/passwd`.
2. For authorized target validation, request permission to use a program-approved canary file or environment marker.
3. Confirm that network entities remain blocked by `LIBXML_NONET`; report this as local-file disclosure / parser configuration drift, not generic SSRF unless a separate network path exists.

Reporting heuristic: strong reports show **attacker-controlled XML reaches DomCrawler and expands a local file entity**. Include exact XML, parser path, package version, and the minimal leaked marker.

### 6. Mail header, SMTP command, and sendmail argument injection

Where to look:

- Applications that accept user-controlled email addresses, display names, attachment/header parameter names, reply-to values, bounce addresses, or mailing-list metadata before passing them to Symfony Mailer/Mime.
- `symfony/mime` / `symfony/mailer` / `symfony/symfony` versions before `5.4.52`, `6.4.40`, `7.4.12`, or `8.0.12`.
- `sendmail://...` transports using `-t` mode, where recipient addresses become command-line arguments.

Safe validation path:

1. Use a non-delivering mail sink, staging transport, or `gmail-no-send`-style equivalent where available; do not send unsolicited mail.
2. Test CRLF only with addresses and parameter names under your control, looking for additional rendered headers or SMTP protocol lines in captured mail source.
3. Test dash-prefixed recipients only in a lab mailer/sendmail wrapper, verifying whether `--` separates options from recipients.
4. Record whether the application canonicalizes, validates, or blocks the value before it reaches Symfony.

Reporting heuristic: impactful reports show **untrusted input enters a supposedly validated mail boundary and emerges as a new header, SMTP command, or sendmail option**. Capture raw input, generated message source / SMTP transcript, and transport mode.

## Non-signal this hour

Reviewed but not promoted as standalone Skillz guidance:

- `GHSA-hmr5-2xcr-v8pp` / `CVE-2026-45072` Symfony WebProfiler non-PHP file-excerpt stored XSS. It can matter in dev environments after a separate file-write primitive, but it is debug-only and was kept as adjacent chain context rather than a new operator page section.
- CISA KEV remained catalog `2026.05.27` with Nx Console, TanStack, and Daemon Tools Lite entries already noted earlier today; no new Skillz operator workflow was added from KEV in this pass.
- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits feed stayed on the already-covered zizmor GitHub Actions static-analysis article.
- ProjectDiscovery RSS stayed on already-covered Neo / Nuclei / DAST proof-loop material; `/blog/rss.xml` still returned 404.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [Symfony MonologBridge `server:log` deserialization advisory (`GHSA-m7v2-7gxm-vc2v`)](https://github.com/advisories/GHSA-m7v2-7gxm-vc2v)
- [Symfony `HEAD` method attribute bypass advisory (`GHSA-6439-2f28-8p8q`)](https://github.com/advisories/GHSA-6439-2f28-8p8q)
- [Symfony CAS service URL host-header advisory (`GHSA-j8gj-9rm5-4xhx`)](https://github.com/advisories/GHSA-j8gj-9rm5-4xhx)
- [Symfony OIDC missing mandatory claims advisory (`GHSA-29fc-p6c4-24cg`)](https://github.com/advisories/GHSA-29fc-p6c4-24cg)
- [Symfony cache `PdoAdapter::clear()` SQL injection advisory (`GHSA-6qh9-h6wf-jgqc`)](https://github.com/advisories/GHSA-6qh9-h6wf-jgqc)
- [Symfony DomCrawler XXE local-file disclosure advisory (`GHSA-x6g4-fwcc-jj8w`)](https://github.com/advisories/GHSA-x6g4-fwcc-jj8w)
- [Symfony Mime address CRLF injection advisory (`GHSA-qpmx-3rfj-7rhv`)](https://github.com/advisories/GHSA-qpmx-3rfj-7rhv)
- [Symfony Mime parameter-name header injection advisory (`GHSA-vqc8-7275-q272`)](https://github.com/advisories/GHSA-vqc8-7275-q272)
- [Symfony Mailer sendmail argument injection advisory (`GHSA-xx3c-qf5g-hc39`)](https://github.com/advisories/GHSA-xx3c-qf5g-hc39)
