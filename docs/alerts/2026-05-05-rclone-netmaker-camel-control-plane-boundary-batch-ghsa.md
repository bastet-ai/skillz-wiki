# Rclone, Netmaker, and Camel control-plane boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced three critical advisories updated after the previous scan: **Rclone CVE-2026-41176 / GHSA-25qr-6mpr-f7qx**, **Netmaker CVE-2026-38651 / GHSA-qpv2-rwc8-c993**, and **Apache Camel CVE-2026-33453 / GHSA-695c-x5gc-94gj**.

## Advisory details

### Rclone RC `options/set` auth bypass

- **Package:** Go `github.com/rclone/rclone`
- **Affected:** `>= 1.45.0, < 1.73.5`
- **Fixed:** `1.73.5`
- **Severity:** Critical, CVSS 9.8
- **Issue:** the remote-control endpoint `options/set` was exposed without `AuthRequired: true` and could mutate the runtime RC option block. On RC servers reachable to an attacker and deployed without global RC HTTP auth, an unauthenticated request could set `rc.NoAuth=true`, disabling authorization checks for many otherwise protected RC methods.
- **References:** <https://github.com/advisories/GHSA-25qr-6mpr-f7qx>, <https://github.com/rclone/rclone/security/advisories/GHSA-25qr-6mpr-f7qx>

### Netmaker host-token signature verification bypass

- **Package:** Go `github.com/gravitl/netmaker`
- **Affected:** `< 1.5.0`
- **Fixed:** `1.5.0`
- **Severity:** Critical, CVSS 8.2
- **Issue:** `VerifyHostToken` parsed host JWTs but did not check `token.Valid` or the parse error. An attacker could forge a JWT with arbitrary signing material, claim another host ID, and retrieve host configuration including credential material and WireGuard peer data.
- **References:** <https://github.com/advisories/GHSA-qpv2-rwc8-c993>, <https://github.com/gravitl/netmaker/commit/5309aa70d464ef565911369714d661a61481a79b>

### Apache Camel CoAP header injection to downstream RCE

- **Package:** Maven `org.apache.camel:camel-coap`
- **Affected:** `>= 4.14.0, <= 4.14.5`; `>= 4.18.0, < 4.18.1`
- **Fixed:** `4.14.6`, `4.18.1`, `4.19.0`
- **Severity:** Critical, CVSS 10.0
- **Issue:** camel-coap mapped CoAP URI query parameters directly into Camel message headers without applying a `HeaderFilterStrategy`. Crafted unauthenticated CoAP requests could inject internal Camel headers. If a route forwarded the exchange to header-sensitive producers such as `camel-exec`, the injected headers could override executable and arguments, leading to command execution as the Camel process.
- **References:** <https://github.com/advisories/GHSA-695c-x5gc-94gj>, <https://camel.apache.org/security/CVE-2026-33453.html>

## Why this is durable

All three advisories are the same control-plane lesson in different clothes:

- Configuration mutation endpoints are privileged actions even when the option being changed looks like ordinary runtime state.
- Token parsing is not authentication unless signature validity and parser errors are explicitly enforced.
- Protocol adapters must not copy untrusted request fields into internal routing headers without a deny-by-default filter.

The reusable bug class is **metadata crossing a trust boundary and becoming authority**. Runtime options became authorization state, unsigned JWT claims became host identity, and CoAP query parameters became privileged Camel headers.

## Immediate triage

1. **Patch exposed services first:** rclone to `1.73.5+`, Netmaker to `1.5.0+`, and Camel CoAP routes to `4.14.6+`, `4.18.1+`, or `4.19.0+`.
2. **Inventory reachability:** locate `rclone rcd` / `--rc` servers, Netmaker API surfaces, and routes using `camel-coap`, especially where CoAP is reachable beyond localhost or trusted networks.
3. **Assume secrets may be exposed** if Netmaker host tokens were accepted from untrusted networks: rotate MQTT credentials, WireGuard material as appropriate, API credentials, and host enrollment material after patching.
4. **Review Camel routes** where CoAP messages flow into `exec`, file, HTTP, dynamic endpoint, scripting, bean, or other header-sensitive producers. Patch first, then add explicit header filtering even if a route appears internal.
5. **Harden rclone RC deployments** with global RC HTTP authentication, localhost-only binding unless strictly required, firewall rules, and monitoring for `options/set` calls or sudden `NoAuth` changes.

## Hunt ideas

- Search process arguments and service units for `rclone rcd`, `--rc`, `--rc-addr`, missing `--rc-user` / `--rc-pass`, and non-loopback listeners.
- Query logs for rclone RC `options/set` requests, especially followed by config, mount, copy, serve, backend, or command-like RC methods.
- In Netmaker, look for host-token requests whose JWT signature would not validate, host IDs switching unexpectedly, or downloads of host configuration from unusual IPs.
- Grep Camel routes for `camel-coap`, `coap:`, `toD`, `exec:`, `CamelExecCommandExecutable`, `CamelExecCommandArgs`, and custom headers that affect downstream producer destinations or commands.
- Add regression tests that send protocol-level query/header parameters matching internal header names and assert they are dropped before route execution.

## Durable controls

- Treat every endpoint that changes authentication, authorization, routing, network, command, or storage behavior as privileged regardless of method name.
- Keep authorization state immutable for the lifetime of a request and never let unauthenticated calls mutate the variables used by the authorization gate.
- For JWTs and signed tokens, require both a valid token object and successful signature/claims validation; fail closed on parser error, missing algorithm constraints, or unexpected key IDs.
- In integration frameworks, maintain explicit inbound-header allowlists per protocol adapter. Drop internal control headers unless a trusted route stage creates them.
- Separate data-plane metadata from control-plane metadata with namespacing, typed wrappers, and tests that prove external input cannot set internal authority-bearing fields.
- Bind administrative APIs to localhost or private management networks by default, and require authentication even when the interface is believed to be local-only.

## Operator lesson

Control metadata is code-adjacent. If an attacker can set the flag that disables auth, forge the claim that selects an identity, or inject the header that selects an executable, they are no longer “just sending data.” They are steering the control plane.
