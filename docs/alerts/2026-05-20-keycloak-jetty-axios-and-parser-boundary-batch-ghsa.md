# Keycloak, Jetty, Axios, and parser-boundary batch

Source: GitHub Security Advisories, updated 2026-05-20:
[GHSA-x4p7-7chp-64hq](https://github.com/advisories/GHSA-x4p7-7chp-64hq),
[GHSA-355h-qmc2-wpwf](https://github.com/advisories/GHSA-355h-qmc2-wpwf),
[GHSA-fvcv-3m26-pcqx](https://github.com/advisories/GHSA-fvcv-3m26-pcqx),
[GHSA-hx9m-jf43-8ffr](https://github.com/advisories/GHSA-hx9m-jf43-8ffr), and
[GHSA-pfr9-2p92-qrhq](https://github.com/advisories/GHSA-pfr9-2p92-qrhq).

This batch is durable because it hits common integration seams: identity brokers accepting assertions after an admin disabled the upstream IdP, HTTP parsers disagreeing on where a chunk ends, HTTP clients inheriting polluted header state, serializers treating regular expressions as safe data, and Rust/C string boundaries assuming null termination.

## What changed

- **Disabled identity provider is not a policy check:** Keycloak SAML IdP-initiated broker logins could accept a valid SAML response from an external IdP even after that IdP was disabled. Affected `org.keycloak:keycloak-services` and `org.keycloak:keycloak-server-spi-private` versions before `26.5.5` should be treated as an authentication-boundary bypass, especially where disabled IdPs were used for emergency access revocation.
- **Chunk-extension parsing can become request smuggling:** Jetty `jetty-http` misparsed CRLF inside quoted chunk-extension values, allowing front/back parser differentials and smuggled requests. Fixed trains are `12.1.7+` and `12.0.33+`; older `11.x`, `10.x`, and `9.4.x` ranges are listed as vulnerable without a first patched version in the advisory.
- **HTTP clients can become gadgets after prototype pollution:** Axios could merge attacker-polluted prototype header values and pass CRLF-containing values into outbound requests. Patched lines are `0.31.0+` and `1.15.0+`; affected services should also remove the upstream prototype-pollution primitive and block metadata/internal-service egress.
- **Serializer feature flags matter:** `seroval` `0.2.0` through `1.4.0` could deserialize attacker-controlled RegExp payloads into memory exhaustion or catastrophic-backtracking DoS. The advisory recommends using the new `disabledFeatures` bitmask and disabling `Feature.RegExp` where regex transport is not required; upgrade to `1.4.1+`.
- **FFI/string conversion needs explicit bounds:** Rust `dbn` `<= 0.22.0` used C-string assumptions in `c_chars_to_str`; non-null-terminated char arrays could make `strlen()` read past the buffer. Upgrade to `0.22.1+` and treat fixed-width binary fields as length-delimited data, not C strings.

## Operator triage

1. **Revalidate disabled Keycloak IdPs.** Upgrade to `26.5.5+`, then review recent broker-login events for disabled SAML IdPs, unexpected external IdP subjects, and sessions minted during the vulnerable window.
2. **Patch Jetty at exposed HTTP boundaries.** Prioritize internet-facing Jetty services, reverse-proxy backends, API gateways, and cache-adjacent deployments. If a branch has no patched version, isolate it behind a parser that rejects malformed chunk extensions or move to a fixed train.
3. **Hunt for Axios gadget chains.** Search for vulnerable Axios plus any parser/config/body library with known prototype-pollution exposure. Rotate cloud/session credentials if outbound requests could reach metadata or internal control-plane services.
4. **Disable risky serialization features by default.** Treat RegExp, function, class, and large object graph serialization as opt-in features with size/time limits and fuzz tests.
5. **Audit binary parser boundaries.** For Rust/C interop and market-data or telemetry formats, enforce explicit lengths, null-byte invariants, and ASAN/fuzz coverage around fixed-width string fields.

## Replayable validation boundaries

- **SAML broker disabled-IdP test:** disable a SAML IdP, replay a valid IdP-initiated SAML response to the broker endpoint, and confirm login fails before session creation.
- **Chunked parser differential test:** send chunk extensions containing quoted-string CRLF sequences through the real proxy/backend chain and confirm the entire request is rejected consistently with one response per connection.
- **Axios CRLF header test:** simulate polluted prototypes in a disposable app and verify patched Axios rejects CRLF header values before socket write; also confirm metadata IPs and internal hosts are blocked at egress.
- **Serializer DoS test:** deserialize oversized and catastrophic RegExp payloads with production feature flags; expected result is feature-disabled rejection or bounded resource use.
- **Fixed-width string fuzz test:** fuzz binary records without null terminators and with maximum-length fields; expected result is bounded parsing with no out-of-bounds read or panic.

## Durable controls

- Treat administrative disablement as an authorization decision that must be checked at every login/assertion entrypoint, not just in UI discovery flows.
- Normalize HTTP parser behavior by rejecting ambiguous framing at the edge and testing the same malformed corpus against every proxy/backend combination.
- Do not let inherited object properties become outbound request headers, URLs, or credentials; merge only own properties and validate CRLF before transport.
- Make serializer capabilities explicit and least-privilege. Disable RegExp/function-like features unless a documented caller needs them.
- Prefer length-delimited parsing over C-string assumptions at language boundaries, even in memory-safe languages that call unsafe/FFI helpers.
