# PKI, MCP, proxy-auth, updater, and cryptographic boundary checks

Sources: hourly offensive-security scan, 2026-07-21 GitHub Security Advisory wave. Primary entries: [GHSA-8r5m-3f66-qpr3](https://github.com/advisories/GHSA-8r5m-3f66-qpr3), [GHSA-c4hg-6933-x62x](https://github.com/advisories/GHSA-c4hg-6933-x62x), [GHSA-7x63-xv5r-3p2x](https://github.com/advisories/GHSA-7x63-xv5r-3p2x), [GHSA-hg88-v3cw-3qrh](https://github.com/advisories/GHSA-hg88-v3cw-3qrh), [GHSA-3pvj-jv98-qhjq](https://github.com/advisories/GHSA-3pvj-jv98-qhjq), [GHSA-8qwj-4jxw-m8jw](https://github.com/advisories/GHSA-8qwj-4jxw-m8jw), [GHSA-5jx8-q4cp-rhh6](https://github.com/advisories/GHSA-5jx8-q4cp-rhh6), and [GHSA-7g92-g4vh-hp84](https://github.com/advisories/GHSA-7g92-g4vh-hp84).

This batch is durable because it exposes reusable operator boundaries: DNS-controlled certificate-validation fetches, caller-controlled MCP routing, forwarded-path trust before authentication, signed updater archives gaining a broader filesystem primitive, predictable temporary runtime paths followed by developer tools, broken big-integer edge cases crossing into signature acceptance or signing-key recovery, and API-vs-UI authorization drift around protected integration destinations.

!!! warning "Authorized validation only"
    Use disposable PKI mounts, DNS zones, MCP servers, proxies, updater keys, filesystem trees, cryptographic keys, Grafana instances, and webhook listeners. Keep callbacks owned, commands inert, credentials fake, files synthetic, and proofs marker-only. Never target metadata/internal production services, overwrite real user/system files, sign a malicious production update, recover or use production private keys, change production notification endpoints, or capture live webhook payloads.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-8r5m-3f66-qpr3](https://github.com/advisories/GHSA-8r5m-3f66-qpr3) / CVE-2026-5052 | HashiCorp Vault PKI ACME validation | Attacker-controlled DNS can make HTTP-01 or TLS-ALPN-01 validation requests reach local targets | Treat certificate challenge resolvers as DNS-rebinding and final-destination SSRF surfaces. |
| [GHSA-c4hg-6933-x62x](https://github.com/advisories/GHSA-c4hg-6933-x62x) / CVE-2026-34476 | Apache SkyWalking MCP 0.1.0 | Caller-controlled `SW-URL` steers server-side requests | Inventory MCP headers as tool-routing inputs, not merely metadata. |
| [GHSA-7x63-xv5r-3p2x](https://github.com/advisories/GHSA-7x63-xv5r-3p2x) / CVE-2026-40575 | OAuth2 Proxy in reverse-proxy mode | Client-supplied `X-Forwarded-Uri` can steer `skip_auth_routes` evaluation away from the upstream path | Compare edge, auth proxy, and backend path decisions with direct-vs-trusted-proxy controls. |
| [GHSA-hg88-v3cw-3qrh](https://github.com/advisories/GHSA-hg88-v3cw-3qrh) | Sparkle binary delta updater | Signed archive content can create an intermediate symlink and make a later extraction escape the update tree | Model compromised signing-key impact against updater filesystem privileges, not only bundle replacement. |
| [GHSA-3pvj-jv98-qhjq](https://github.com/advisories/GHSA-3pvj-jv98-qhjq) / CVE-2026-53765 | `chrome-devtools-mcp` daemon fallback under `/tmp` | Predictable runtime directory and symlink-following PID write let another local user redirect a victim-writable file write/truncation | Add parent-directory ownership and final-component symlink checks to local agent daemons. |
| [GHSA-8qwj-4jxw-m8jw](https://github.com/advisories/GHSA-8qwj-4jxw-m8jw) / CVE-2026-4602 | `jsrsasign` before 11.1.1 | Negative exponent handling can produce incorrect modular inverses and break signature verification | Add invalid-domain integer fixtures to crypto verifier assessments and prove accept/reject drift with disposable keys. |
| [GHSA-5jx8-q4cp-rhh6](https://github.com/advisories/GHSA-5jx8-q4cp-rhh6) / CVE-2026-4599 | `jsrsasign` 7.0.0 through before 11.1.1 | Incomplete range comparison biases DSA signing nonces enough for private-key recovery | Assess signer-generated signature corpora offline for nonce bias before any key-recovery proof. |
| [GHSA-7g92-g4vh-hp84](https://github.com/advisories/GHSA-7g92-g4vh-hp84) / CVE-2026-21724 | Grafana OSS provisioning contact-points API | Editor role can modify protected webhook URLs without the protected-receiver write permission | Test API/UI and protected/unprotected receiver authorization as a role-route matrix. |

## Replayable validation boundaries

### ACME challenge final-destination checks

1. Use a disposable Vault PKI mount, an owned DNS zone with short TTLs, and two lab listeners representing public and synthetic local destinations.
2. Request only canary certificates for the owned zone and record DNS answers plus connection destinations for HTTP-01 and TLS-ALPN-01.
3. If rebinding or time-of-check/time-of-use testing is approved, switch only between owned lab addresses and compare the validated address with the address actually dialed.
4. Add controls for patched Vault, stable public DNS, non-local final addresses, redirects if the challenge client follows them, and failed challenge tokens.

Report **attacker-controlled ACME identifier/DNS -> challenge validation -> request reaches a synthetic local destination**. Do not query metadata, loopback admin services, Kubernetes APIs, or third-party private hosts.

### MCP upstream-header routing checks

Run SkyWalking MCP 0.1.0 against an owned mock SkyWalking API. Vary `SW-URL` between the configured mock, another owned listener, loopback syntax variants, an owned redirector, malformed values, and patched 0.2.0. Evidence should identify whether the header overrides the server's expected upstream, which process makes the request, and which final owned destination receives it. Report **MCP caller header -> upstream base URL selection -> server-origin fetch to caller-selected canary**. Never point it at production monitoring systems or internal services.

### Forwarded-path authentication matrices

1. Put an owned edge proxy, OAuth2 Proxy, and marker backend in sequence. Enable reverse-proxy mode and define one harmless skip-auth route plus one protected marker route.
2. Test the protected and public routes with no forwarded header, a truthful edge-overwritten `X-Forwarded-Uri`, and a client-supplied value naming the public route.
3. Repeat from direct-client and trusted-edge source addresses. On 7.15.2 or later, compare unset and explicitly scoped `--trusted-proxy-ip`; upgrading alone preserves broad trust when the flag remains unset.
4. Record the wire request URI, forwarded URI, source class, skip-auth decision, backend path, session state, and status/body marker.

Report **client-controlled forwarded path -> skip-auth rule evaluates a different route -> protected marker backend reached without a canary session**. Stop at the synthetic route; do not access real user or admin data.

### Signed updater symlink-boundary checks

Use a disposable Sparkle app, throwaway EdDSA key, non-root updater process, temporary extraction root, and sibling marker directory. Create a signed delta that contains an intermediate symlink followed by a benign file under that path. Prove only whether the file lands in the sibling canary directory. Compare immediate-parent and deeper intermediate-symlink cases and a fixed build. State the signing-key-compromise precondition explicitly: this expands the filesystem effect available to a signing-key holder and is not an unsigned-update bypass. Do not overwrite bundles, startup files, or system paths.

### Predictable runtime-directory symlink checks

On a two-user disposable macOS/Linux lab where `XDG_RUNTIME_DIR` is unset, pre-create only the expected `/tmp/chrome-devtools-mcp-<uid>` path for the victim test user and redirect `daemon.pid` to a victim-owned temporary marker file. Start daemon mode as the victim and record directory ownership, symlink resolution, target size/content, and process result. Compare a private runtime directory and a fixed build using secure parent ownership plus no-follow/exclusive creation. Never target shell profiles, SSH files, browser profiles, or real configuration.

### `jsrsasign` verification and nonce-bias checks

For negative-exponent verification behavior, create disposable RSA/DSA keys and a local harness that invokes the exact affected verification path. Start with valid signatures and ordinary invalid signatures, then add only the malformed mathematical-domain fixture from the upstream advisory/reproducer. Compare vulnerable and 11.1.1-or-later accept/reject/error decisions. Keep all tokens and keys offline and synthetic.

For DSA nonce bias, generate a bounded corpus of signatures over known synthetic messages with one disposable key. Record `(r, s)`, message hashes, library version, and sampling configuration; then run the upstream statistical/key-recovery reproducer offline. A strong proof first demonstrates distribution bias, then—only in the disposable harness—confirms whether a recovered candidate matches the throwaway public key. Do not collect signatures from production signers, brute-force real keys, or use a recovered key for token or document forgery.

Report either **malformed integer domain -> verifier accepts a signature the fixed implementation rejects** or **biased signer nonce distribution -> disposable DSA private key recovered offline**. Do not generalize to application authentication without proving the target uses the affected library and algorithm path.

### Grafana protected-contact-point authorization checks

1. Create a disposable Grafana OSS instance, one Editor user, one contact point whose webhook URL is marked protected, and two owned marker-only webhook listeners.
2. Establish controls: the Editor can view/use only the actions intended by the configured role and cannot change the protected URL through the normal UI path.
3. Through the provisioning contact-points API, attempt to replace only the synthetic protected webhook URL with the second owned listener while preserving all unrelated fields.
4. Trigger one harmless test notification containing no dashboard, alert, label, or tenant data and record which owned listener receives the marker.
5. Compare Grafana 12.3.6 or later, a user holding the explicit protected-receiver write permission, an unprotected receiver, and a Viewer role.

Report **Editor provisioning API access -> protected field write check omitted -> synthetic notification destination changes**. Restore/delete the disposable receiver and never redirect production alerts or capture real alert payloads.

## Reporting checklist

- [ ] Did the report prove the caller can reach the exact PKI, MCP, proxy, updater, daemon, cryptographic, or provisioning path?
- [ ] Are DNS answers, final destinations, forwarded paths, archive entries, filesystem resolution, signature decisions, and role-route outcomes shown as decision tables or diffs?
- [ ] Are keys disposable, callbacks owned, credentials fake, payloads inert, and files synthetic?
- [ ] Does each finding include a patched or policy-negative control?
- [ ] Are configuration-dependent preconditions explicit, especially ACME challenge type, reverse-proxy/skip-auth settings, signing-key control, `/tmp` fallback, algorithm path, and Grafana role/permission state?
