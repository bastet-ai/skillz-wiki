# Eclipse Jetty path, authority, trailer-state, and Digest-auth boundary checks

Sources: [GHSA-w7x5-g22v-xqhr / CVE-2026-8384](https://github.com/advisories/GHSA-w7x5-g22v-xqhr), [GHSA-7p3p-8qv8-m2vh / CVE-2026-6790](https://github.com/advisories/GHSA-7p3p-8qv8-m2vh), [GHSA-f4v5-65jj-pcr2 / CVE-2026-10051](https://github.com/advisories/GHSA-f4v5-65jj-pcr2), and [GHSA-2fvj-hgj9-j2gr / CVE-2026-10050](https://github.com/advisories/GHSA-2fvj-hgj9-j2gr), published July 22, 2026.

These advisories expose four durable Jetty tests: canonicalization before path security, HTTP/2 or HTTP/3 authority consistency, connection-scoped trailer state crossing request boundaries, and lossy character encoding inside Digest authentication. Package presence is not sufficient; each path needs a matching application policy or authentication consumer.

!!! warning "Authorized lab validation only"
    Use a disposable Jetty service, synthetic routes and users, raw-byte captures, and one controlled keep-alive connection. Do not target production authentication, tenant routing, caches, or cross-user traffic.

## Boundary matrix

| Advisory | Preconditions | Narrow proof |
| --- | --- | --- |
| [GHSA-w7x5-g22v-xqhr](https://github.com/advisories/GHSA-w7x5-g22v-xqhr) | Jetty 12 path-mapped security protects a prefix and the request target includes a semicolon path parameter followed by slash/dot segments | A normal `/admin/marker` is denied while a path-parameter variant reaches the same marker handler without the constraint. Fixed in 12.0.35 and 12.1.9. |
| [GHSA-7p3p-8qv8-m2vh](https://github.com/advisories/GHSA-7p3p-8qv8-m2vh) | HTTP/2 or HTTP/3 reaches Jetty and application/proxy policy consumes host identity in more than one representation | `:authority` and `Host` disagree; `Request.getServerName()` and raw-header consumers make different synthetic tenant/routing decisions. Fixed in 12.0.35 and 12.1.9; consult the advisory for older branches without a listed patched release. |
| [GHSA-f4v5-65jj-pcr2](https://github.com/advisories/GHSA-f4v5-65jj-pcr2) | Two HTTP/1.1 requests share one keep-alive connection and application logic reads request trailers | Request N's canary trailer appears in trailer state for request N+1, which sent none. Fixed in 12.0.36 and 12.1.10. |
| [GHSA-2fvj-hgj9-j2gr](https://github.com/advisories/GHSA-2fvj-hgj9-j2gr) | Jetty HTTP client Digest authentication uses a password containing characters outside ISO-8859-1 | Replacing each unencodable character with `?` produces the same lab Digest result. Fixed in 9.4.63, 10.0.31, 11.0.31, 12.0.36, and 12.1.10. |

## Replayable lab workflow

### Path-parameter normalization

Create `/public/marker` and `/admin/secret-canary`, protect `/admin/*`, and log the raw target, parsed path parameters, canonical path, constraint match, and final handler. Compare ordinary slash/dot segments with a harmless path-parameter traversal canary, encoded delimiters, and reordered parameters. A positive result is **security matcher sees an incompletely normalized path -> protected handler sees the resolved admin path**. Retrieve only the synthetic marker.

### HTTP authority decision table

Use an HTTP/2-capable lab client and two owned virtual-host markers. Send matched and mismatched `:authority`/`Host` values and capture the protocol frames plus values observed by raw headers, `HttpURI`, `Request.getServerName()`, virtual-host routing, callback construction, and any cache/auth policy fixture. Repeat over HTTP/1.1 and, if available, HTTP/3. Do not claim tenant escape unless the application actually makes a security-sensitive decision on the divergent representations.

### Keep-alive trailer-state harness

On one raw HTTP/1.1 connection, send request A with `Transfer-Encoding: chunked` and a unique trailer, then request B without trailers. Have both handlers return only whether the expected canary trailer exists. Reverse order, open a new connection, and test two trailer names as controls. Positive evidence is **connection-scoped trailer object populated by A -> not reset -> B observes A's marker**. Do not involve another user or shared production connection.

### Digest character-substitution check

Create a disposable Digest realm and user whose password contains known non-Latin-1 canary characters. Capture the nonce/realm in the lab, compare the real password with a same-length `?` substitution and unrelated controls, and record only authentication result and locally computed response hashes. The issue is in Jetty's HTTP client credential encoding; verify that the assessed product actually uses that client path before reporting. Never attempt this against a real account or retain reusable credentials.

## Reporting

Lead with **path parameter to incomplete canonicalization before security matching**, **HTTP pseudo-header/header disagreement to split host identity**, **request N trailer to request N+1 state**, or **Unicode credential text to lossy Latin-1 Digest bytes**. Include Jetty module, protocol version, release, route/auth fixture, raw-byte evidence, and fixed-version comparison. The adjacent `100-Continue` out-of-memory advisory was tracked without publication because it adds only availability impact.
