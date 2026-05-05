# Axios prototype-pollution client-boundary batch (GHSA)

**Signal:** GitHub Security Advisories published a **2026-05-05** Axios batch showing how one prototype-pollution primitive elsewhere in a Node or browser application can turn a trusted HTTP client into a response-tampering, header-injection, credential-exfiltration, or proxy-bypass gadget.

## Advisories in this batch

- **Response tampering, data exfiltration, and request hijacking** — `axios >= 1.0.0, < 1.15.1` and `axios <= 0.31.0` can be abused after `Object.prototype` pollution to alter JSON responses or hijack the underlying HTTP transport. Fixed in 1.15.1 and 0.31.1. Reference: <https://github.com/advisories/GHSA-pf86-5x62-jrwf>.
- **Header injection through HTTP-adapter FormData duck typing** — polluted `getHeaders`, `append`, `pipe`, event handlers, and `Symbol.toStringTag` can make plain objects look like FormData and merge attacker-controlled headers into outgoing requests. Affects `axios >= 1.0.0, < 1.15.1` and `<= 0.31.0`; fixed in 1.15.1 and 0.31.1. Reference: <https://github.com/advisories/GHSA-6chq-wfr3-2hj9>.
- **XSRF token cross-origin leakage** — non-boolean truthy `withXSRFToken`, including values inherited through pollution, can bypass the same-origin check in browser environments and send XSRF tokens to attacker-controlled origins. Affects `axios >= 1.0.0, < 1.15.1` and `<= 0.31.0`; fixed in 1.15.1 and 0.31.1. Reference: <https://github.com/advisories/GHSA-xx6v-rp6x-q39c>.
- **`validateStatus` auth-bypass gadget** — polluted config can make callers treat attacker-chosen HTTP status codes as successful, bypassing downstream auth or business-logic gates that rely on rejected responses. Affects `axios >= 1.0.0, < 1.15.1` and `<= 0.31.0`; fixed in 1.15.1 and 0.31.1. Reference: <https://github.com/advisories/GHSA-w9j2-pvgh-6h63>.
- **NO_PROXY loopback subnet bypass** — an incomplete fix for CVE-2025-62718 missed RFC 1122 loopback forms in `127.0.0.0/8`, letting traffic that should bypass proxies be routed through a proxy. Affects `axios >= 1.0.0, < 1.15.1` and `<= 0.31.0`; fixed in 1.15.1 and 0.31.1. Reference: <https://github.com/advisories/GHSA-pmwg-cvhr-8vh7>.
- **Invisible JSON response tampering via `parseReviver`** — `axios >= 1.0.0, < 1.15.2` can inherit a polluted `parseReviver` and silently mutate parsed JSON. Fixed in 1.15.2. Reference: <https://github.com/advisories/GHSA-3w6x-2g7m-8v23>.
- **Read-side HTTP-adapter credential injection and request hijacking** — `axios >= 1.0.0, < 1.15.2` had additional prototype-read gadgets in the HTTP adapter. Fixed in 1.15.2. Reference: <https://github.com/advisories/GHSA-q8qp-cvcw-x6jj>.
- **Null-byte injection through reverse encoding in `AxiosURLSearchParams`** — `axios >= 1.0.0, < 1.15.1` and `<= 0.31.0` can encode values in ways that reintroduce null-byte semantics across downstream parsers. Fixed in 1.15.1 and 0.31.1. Reference: <https://github.com/advisories/GHSA-xhjh-pmcv-23jw>.

## Why this is durable

Prototype pollution is not only a source vulnerability. It is also a **sink class**: every library that reads inherited properties at a trust boundary can become the exploit gadget after some other package polluted the prototype.

HTTP clients are especially sensitive because they sit between application authority and the network. A polluted client config can change destinations, headers, request bodies, proxy routing, response parsing, status handling, and browser credential behavior without touching call sites.

## Immediate triage

1. Upgrade Axios to **1.15.2 or later** wherever possible. If pinned to the legacy 0.x line, move to **0.31.1** at minimum, then plan a major-version migration.
2. Prioritize apps that combine Axios with deep-merge, querystring, YAML/JSON parser, deserializer, or plugin surfaces that accept attacker-controlled object keys.
3. Search dependency graphs for known prototype-pollution sources and treat those findings as potential Axios-gadget exposure, not as isolated low-severity bugs.
4. Review browser Axios calls that rely on cookies, XSRF tokens, or same-origin defaults; verify cross-origin requests cannot inherit `withXSRFToken` or credential-like config.
5. Review server-side Axios calls to internal services, metadata endpoints, admin APIs, and signed upstreams for proxy, header, and status-code trust assumptions.

## Hunt ideas

- Grep logs and telemetry for unusual outbound headers, attacker-shaped `Content-Type`, unexpected `Proxy-*` headers, or requests to loopback/private ranges routed through configured proxies.
- In browser telemetry, look for cross-origin Axios requests that include XSRF headers or cookies where the call site did not explicitly opt in.
- Add canary tests that pollute `Object.prototype` with representative keys (`getHeaders`, `withXSRFToken`, `validateStatus`, `parseReviver`, proxy fields) and assert client behavior is unchanged.
- Trace code paths where response status controls authorization, payment, provisioning, or workflow transitions; make success criteria explicit instead of inheriting Axios defaults.

## Durable controls

- Create HTTP-client config objects with null prototypes or hardened schemas; never rely on inherited properties for security-sensitive request behavior.
- Freeze or sanitize global prototypes in high-risk runtimes and fail tests when pollution can affect network sinks.
- Use explicit allowlists for outbound destinations, proxy use, and credential-bearing headers at the egress layer, not only in client-library config.
- Normalize loopback, IPv4-mapped IPv6, integer/octal/hex IPv4, DNS rebinding, and private-range forms before proxy or SSRF policy decisions.
- Treat response parsers and status mappers as security-sensitive code; make JSON revivers and acceptable status ranges local, typed, and non-inheritable.

## Operator lesson

When a process has prototype pollution anywhere, every inherited-property read in an HTTP client becomes part of the attack surface. Patch Axios, but also hunt for the pollution primitive and move network authority behind explicit, non-inheritable policy.
