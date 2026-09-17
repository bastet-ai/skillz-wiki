# FatPipe EOL-firmware management-plane preauth root RCE pair

Source: GitHub Security Advisories published 2026-09-17T12:32Z wave: [GHSA-h64v-87jf-gq9c](https://github.com/advisories/GHSA-h64v-87jf-gq9c) / CVE-2026-90822 (critical) and [GHSA-32q2-w7qg-44p8](https://github.com/advisories/GHSA-32q2-w7qg-44p8) / CVE-2026-90823 (critical). Affected: FatPipe MPVPN, WARP, and IPVPN appliances running end-of-life firmware **10.1.2r60p100**.

Two unauthenticated root code-execution primitives on the same end-of-life appliance line, one in the web management auth path and one in the auth backend binary:

- **OS command injection via `AuthFormServlet` → `xtremed` daemon (CVE-2026-90822).** Authentication data submitted to the management interface's login form is processed through a shell by the `xtremed` daemon. Unauthenticated, remote, executes as **root**. The injection point is the authentication data itself — the login form is the exploit surface.
- **Stack-based buffer overflow in `/usr/sbin/auth_user_pass` (CVE-2026-90823).** A crafted authentication request reaches an unchecked copy into a fixed-size stack buffer — arbitrary code execution as **root**. Again, the login request is the payload channel.

Vendor caveat that matters for scoping: **the affected management interface is disabled by default** and must be affirmatively enabled by the customer before the endpoint becomes reachable. EOL firmware means no vendor fix path — presence of the reachable interface *is* the finding.

!!! warning "Authorized targets only"
    These are perimeter VPN/routing appliances. Validate only against infrastructure you own or are explicitly engaged to test. All command-execution proofs stop at lab-owned appliances or firmware-emulated sinks; never run commands against a customer production appliance.

## Why this is durable operator guidance

1. **Default-disabled does not mean absent.** FatPipe's exposure model (management plane reachable only if the admin enabled it) is identical to the Ivanti Sentry / PeopleSoft UEM pattern already documented on this wiki: the security-relevant recon question is *management-interface exposure state*, not product presence. A banner/API response confirming 10.1.2r60p100 plus a TCP-reachable management port is a critical finding on its own because the firmware is EOL — there is no patch, only removal or network isolation.
2. **The login form is the attack surface, not a post-auth surface.** Both primitives land in the authentication handlers (`AuthFormServlet` path, `auth_user_pass` binary). Operator implication for any appliance login page: shape-test the credential fields themselves (length-overflow patterns, shell metacharacter canaries in *lab* only) as a first-class unauthenticated surface, not just for brute-force. Response/timing differences between malformed-length and malformed-syntax submissions fingerprint the parser class (stack copy vs shell interpolation).
3. **EOL firmware fingerprinting is a prioritization primitive.** When recon identifies a product line with known EOL firmware trains, enumerate the version first (banner, `/`-page markup, TLS cert CN, product-specific error shapes) before touching any endpoint; hitting a known-EOL version with a reachable management plane reorders the entire engagement queue.

## Replayable validation boundaries (lab or explicit customer approval only)

1. **Version + exposure evidence first:** capture management-port reachability (service banner, TLS fingerprint, login page hash) and any version token. Positive: management interface reachable + version within the affected train. No exploit traffic needed for the finding itself.
2. **Parser-class differentiation (lab appliance only):** submit over-long and metacharacter-bearing values in the username field of the login form against your *own* lab appliance; record response shape/connection-reset/latency differential. A daemon crash or restart is the (accidental) confirmation — stop there; do not craft working payloads for a live device.
3. **Interface-enabled inventory:** for multi-appliance estates, script the reachability check across the fleet and report the enabled/disabled matrix — default-disabled instances should be listed as "not exposed" so the finding survives triage.

## Reporting heuristics

- Title as **FatPipe EOL 10.1.2r60p100 management interface: unauthenticated preauth root command injection (`AuthFormServlet`/`xtremed`) and stack overflow (`auth_user_pass`)**; cite reachability evidence and version token, and state explicitly that the interface was affirmatively enabled (customer-side exposure decision, EOL = no patch).
- Do not publish working payloads for either primitive; report at the boundary (reachable auth handler on EOL firmware) with the CVE/GHSA references.
- Recommend-boundary language only (isolation/removal) since no fixed firmware exists; keep the page's operator focus on detection of exposure state and safe parser-class evidence.

## Safety

- Own-owned or explicitly-engaged appliances only; never test ISP/carrier-side infrastructure.
- No payload development against live customer devices; crash-inducing traffic on a production VPN concentrator is an outage.
- Evidence = exposure state, version token, response differentials; not RCE confirmation on live hosts.

---

*Source: hourly offensive-security scan, 2026-09-17 (12:32Z GitHub advisory wave). Tracked in the [source index](../notes/source-index.md).*
