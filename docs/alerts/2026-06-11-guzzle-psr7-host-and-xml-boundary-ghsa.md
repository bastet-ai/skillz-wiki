# Guzzle PSR-7 host and XML serialization boundary checks

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-hq7v-mx3g-29hw](https://github.com/advisories/GHSA-hq7v-mx3g-29hw) / CVE-2026-49214 for `guzzlehttp/psr7` CRLF injection through URI host serialization, [GHSA-34xg-wgjx-8xph](https://github.com/advisories/GHSA-34xg-wgjx-8xph) / CVE-2026-48998 for `guzzlehttp/psr7` host confusion through authority reinterpretation, and [GHSA-q8r6-5hfw-5jff](https://github.com/advisories/GHSA-q8r6-5hfw-5jff) / CVE-2026-53723 for `guzzlehttp/guzzle-services` XML CDATA terminator injection.

This is durable for operators because the advisories expose two reusable PHP integration test classes: **untrusted URL or Host material crosses into PSR-7 request construction/serialization**, and **untrusted scalar input crosses into modeled XML request bodies without preserving the intended text-node boundary**.

## Why it matters for assessments

Guzzle is common in PHP API clients, webhook dispatchers, crawlers, gateways, SDK wrappers, and service-to-service integrations. A vulnerable dependency alone is not enough. The practical question is whether an in-scope user, tenant, webhook sender, imported record, or upstream service can influence one of these boundaries:

- a URL that becomes a PSR-7 `Uri` or `Request` and is later serialized into a raw HTTP/1.x request;
- an inbound raw HTTP request or `Host` server variable parsed by `GuzzleHttp\Psr7\Message::parseRequest()`, legacy `parse_request()`, `ServerRequest::fromGlobals()`, or `ServerRequest::getUriFromGlobals()`;
- a `guzzlehttp/guzzle-services` service-description parameter with `location: xml` populated from untrusted input;
- `additionalParameters` that are serialized as XML element text for a downstream service.

Do not report every Composer lockfile hit as exploitable. The useful finding is a reachable boundary where the application trusts the parsed host, serialized Host header, or generated XML structure for routing, allow-listing, credential choice, forwarding, or privileged downstream operation semantics.

## What to map first

1. Confirm authorization for dependency-to-integration validation. Keep all network and XML tests in a lab, staging target, or customer-approved canary tenant.
2. Identify affected packages and versions:
   - `guzzlehttp/psr7` before `2.10.2` for the two host-boundary advisories; `1.x` is end-of-life.
   - `guzzlehttp/guzzle-services` versions covered by GHSA-q8r6-5hfw-5jff when XML request serialization is used.
3. Trace data flow from external input to one of the affected APIs. Prioritize:
   - webhook, callback, URL-preview, crawler, and federation features;
   - reverse-proxy, gateway, HTTP-message replay, testing, or debug tooling that manually serializes PSR-7 requests;
   - multi-tenant SDK wrappers that convert tenant profile/order/account fields into XML API requests;
   - integrations where the downstream XML service honors duplicated or unexpected elements.
4. Build a minimal canary proof. Do not aim these tests at production third-party endpoints unless the assessment scope explicitly permits it.
5. Capture only canary hostnames, headers, XML fields, and mock-service transcripts.

## PSR-7 host CRLF serialization boundary

The CRLF advisory requires more than constructing a URI object. The risky flow is: user-controlled URL -> PSR-7 URI or request -> raw HTTP/1.x serialization with the host copied into the `Host` header -> network write, proxy handoff, or downstream parser.

Safe lab canary shapes:

```text
https://canary.example.test\r\nX-Skillz-Canary: yes/path
http://canary.example.test%0d%0aX-Skillz-Canary:%20yes/path
```

Use them only in a local harness or approved staging path. The proof should show whether raw serialization emits an additional header line such as `X-Skillz-Canary: yes`. Do not use payloads that target cache poisoning, credential theft, cross-user desync, or production request smuggling.

If the application uses only the normal `guzzlehttp/guzzle` HTTP client send path and never manually serializes raw PSR-7 messages, document that this specific boundary was not reached.

## PSR-7 Host authority reinterpretation boundary

The host-confusion advisory concerns inbound request parsing and server request construction, not standard outbound Guzzle client usage. Focus on code paths where a parsed URI host drives routing, allow-list checks, credential selection, or forwarding.

Safe lab canary shapes:

```text
Host: trusted.example.test@attacker-canary.example.test
Host: allowed.example.test:443@attacker-canary.example.test
```

Useful evidence is a mismatch table:

| Input Host header | Application-observed Host header | Parsed PSR-7 URI host | Decision using parsed host |
| --- | --- | --- | --- |
| `trusted.example.test@attacker-canary.example.test` | `trusted.example.test@attacker-canary.example.test` | `attacker-canary.example.test` | routed/forwarded/allowed |

Only claim impact that the canary proves. A mismatch in a dead diagnostic endpoint is not the same as SSRF, credential forwarding, or tenant routing bypass.

## Guzzle Services XML CDATA terminator boundary

The XML advisory is about outgoing request-body integrity. It applies when `guzzlehttp/guzzle-services` serializes an XML element text value that can contain the CDATA terminator `]]>`. The attacker does not need to control the service description if an existing modeled XML parameter is populated from untrusted input.

Safe lab canary value for a text element such as `DisplayName`:

```text
Alice]]></DisplayName><SkillzCanary>yes</SkillzCanary><DisplayName><![CDATA[
```

Expected lab evidence is a generated XML request body where `SkillzCanary` appears as a sibling element outside the intended text node. Keep the downstream service disposable or mocked. Do not inject privileged real fields such as account roles, payment flags, production resource IDs, or live customer identifiers in public evidence.

If the parameter is serialized as an XML attribute, constrained by a safe enum/pattern, or filtered to exclude `]]>`, document that the tested path does not meet the advisory preconditions.

## Evidence to capture

Strong evidence includes:

- exact package name and vulnerable version from `composer.lock`, SBOM, or runtime metadata;
- the reachable feature that accepts untrusted URL, Host, or XML-bound field input;
- the specific Guzzle API reached by that feature;
- sanitized canary input and the resulting raw HTTP request, parsed-host mismatch, or generated XML body;
- whether validation occurs before Guzzle or only after parsing/serialization;
- a clear statement of the demonstrated impact boundary: header injection in a lab serializer, host reinterpretation in a gateway/parser path, or XML element injection into a mocked downstream request.

## Reporting heuristics

- Lead with the integration boundary, not the package name.
- Separate the three advisories. CRLF host serialization, inbound Host reinterpretation, and XML CDATA terminator injection have different prerequisites.
- Avoid claiming Guzzle standard HTTP-client exploitation unless the application actually serializes or forwards raw PSR-7 requests in the vulnerable way.
- For XML, show the intended element and injected canary element side by side.
- Keep proofs canary-only and authorized; do not demonstrate credential forwarding, cache poisoning, production desync, or privileged XML field changes unless explicitly scoped in a disposable environment.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, CISA KEV, and GitHub advisory feeds. No new non-GitHub source item produced separate durable operator guidance this hour. Previously processed PDM, Litestar, Claude Code Action, OpenTelemetry, Anyquery, vLLM, Keycloak, Undertow, Netty, and availability-only items remained represented by existing wiki coverage or did not justify a separate offensive workflow page.
