# Netty DNS and Redis codec protocol-boundary checks

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-cm33-6792-r9fm](https://github.com/advisories/GHSA-cm33-6792-r9fm) / CVE-2026-42579 for Netty `codec-dns` input validation bypass, and [GHSA-rgrr-p7gp-5xj7](https://github.com/advisories/GHSA-rgrr-p7gp-5xj7) / CVE-2026-42586 for Netty `codec-redis` CRLF injection.

This is durable for operators because both advisories expose the same reusable test class: **application-controlled protocol tokens cross into a Netty encoder/decoder without enforcing the delimiter, length, or grammar rules that downstream protocol peers rely on**.

## Why it matters for assessments

Netty is often buried inside Java service clients, API gateways, sidecars, proxies, and bespoke integration services. A dependency finding is only useful when it maps to an attacker-controlled protocol boundary. For these advisories, the operator value is in finding places where user, tenant, webhook, or upstream service input becomes one of these protocol fields:

- DNS query names handled by `io.netty:netty-codec-dns`;
- DNS responses accepted from a controlled or semi-controlled resolver path;
- Redis inline commands built with `InlineCommandRedisMessage`;
- Redis simple-string or error responses relayed by a Netty Redis proxy or middleware;
- diagnostic, cache, queue, or feature-flag tooling that constructs Redis commands from request parameters.

Do not treat every transitive Netty dependency as exploitable. The practical boundary is: **can an in-scope actor influence the DNS name, DNS response, Redis inline command content, or Redis text response content before Netty serializes or parses it?**

## What to map first

1. Confirm written authorization for dependency-to-protocol validation. DNS and Redis tests can affect shared infrastructure if aimed at production resolvers or data stores.
2. Identify Java services that include either module:
   - `io.netty:netty-codec-dns` at vulnerable versions up to `4.1.132.Final` or `4.2.12.Final`;
   - `io.netty:netty-codec-redis` at vulnerable versions up to `4.1.132.Final` or `4.2.12.Final`.
3. Trace whether untrusted input reaches the relevant Netty message constructors or resolver paths. Prioritize:
   - webhook fetchers, URL previewers, SSRF-adjacent components, crawler jobs, and tenant-configured callback domains;
   - Redis proxies, admin consoles, cache-debug endpoints, queue-inspection tools, and custom Redis clients;
   - services that accept a user-supplied hostname and perform asynchronous Netty DNS resolution rather than JDK-only resolution.
4. Build a disposable lab or customer-approved test tenant. Use canary domains, canary Redis keys, and test-only Redis databases.
5. Keep validation non-destructive: no production key deletion, no secret reads, no cache flushing, and no attempts to poison shared resolvers.

## DNS codec validation boundary

The DNS advisory highlights three validation gaps that matter during authorized testing:

- null bytes embedded in labels, creating possible interpretation differences across Java strings, DNS packets, and C/native consumers;
- labels longer than the RFC 1035 63-byte limit, where high length values can collide with compression-pointer ranges in other parsers;
- empty labels in the middle of a name, where the encoded name may stop earlier than the application-level string implies.

Safe canary inputs for a lab resolver harness:

```text
safe-canary.example.test
safe-canary..suffix.example.test
longlabel-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.test
null-byte-canary\x00suffix.example.test
```

Record whether the application rejects the input before Netty, what DNS packet is emitted in the lab, and which name the resolver or downstream parser observes. The useful proof is a **string-to-wire mismatch** or **wire-to-decoder mismatch**, not a broad DNS poisoning attempt.

## Redis codec validation boundary

The Redis advisory is specific to text-delimited Redis message forms, not normal length-prefixed bulk strings. Focus on code paths that use:

- `InlineCommandRedisMessage` for command construction;
- `SimpleStringRedisMessage` or `ErrorRedisMessage` for proxy or middleware responses;
- custom Redis diagnostic features that concatenate command text.

Safe lab canary shape:

```text
GET skillz-canary
<CRLF>
PING skillz-canary
```

Use this only against a disposable Redis instance or a mock server controlled by the assessment. The proof should show that a single user-controlled value creates an extra RESP command boundary or forged text response in the lab. Do not demonstrate destructive Redis commands, credential extraction, `CONFIG`, `MODULE`, `EVAL`, `FLUSH*`, or production key access.

If the service uses `ArrayRedisMessage` plus `BulkStringRedisMessage`, document that the tested path is length-prefixed and not represented by this CRLF boundary unless another text command path exists.

## Evidence to capture

Strong evidence includes:

- exact package name and vulnerable version from the build, SBOM, or runtime classpath;
- the reachable application feature that supplies attacker-controlled input;
- the Netty class or message type reached by that feature;
- sanitized canary input and the corresponding lab wire output or mock-server transcript;
- confirmation that evidence used a disposable resolver, Redis database, tenant, or mock service;
- whether the impact is limited to malformed packet generation, parser differential, command injection precondition, or confirmed canary command boundary.

Keep packet captures and Redis transcripts scoped to canaries. Redact hostnames, tenant IDs, and infrastructure details that are not needed for the public report.

## Reporting heuristics

- Lead with the boundary, not the dependency: **untrusted protocol token reaches Netty DNS/Redis codec without grammar validation**.
- Separate DNS encoder, DNS decoder, and Redis encoder findings. They have different prerequisites and impact.
- For Redis, explicitly state whether the affected path uses inline/simple-string/error messages or length-prefixed bulk strings.
- For DNS, show the application-level string and the observed wire/lab-decoded name side by side.
- Do not claim DNS cache poisoning, Redis RCE, or data theft unless the customer-approved lab proof demonstrates that impact with canary-only artifacts.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, CISA KEV, and GitHub advisory feeds. No new non-GitHub source item produced separate durable operator guidance this hour. Previously processed axios, Keycloak, Undertow, and availability-only updated-feed entries remained represented by existing wiki coverage or did not justify a new offensive workflow page.
