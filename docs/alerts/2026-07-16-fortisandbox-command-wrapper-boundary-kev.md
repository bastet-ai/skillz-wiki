# FortiSandbox command-wrapper boundary checks

Sources: hourly offensive-security scan, 2026-07-16 CISA KEV update. Primary entries: [CVE-2026-25089](https://nvd.nist.gov/vuln/detail/CVE-2026-25089), [CVE-2026-39808](https://nvd.nist.gov/vuln/detail/CVE-2026-39808), and the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

This KEV update is durable for operators because it exposes a reusable appliance boundary: network-reachable FortiSandbox HTTP handlers can cross from request parameters into OS command construction on management surfaces. The useful validation is route ownership, affected-version state, authorization posture, and marker-only command-wrapper control in a lab or explicitly approved customer window — not a public exploit string.

!!! warning "Authorized validation only"
    Keep proofs to synthetic FortiSandbox appliances or explicitly approved customer test windows, owned source IPs, route decision tables, and marker-only commands. Do not publish working appliance RCE payloads, execute commands on appliances outside written scope, alter malware-analysis queues, retrieve submitted samples, read appliance secrets, or create persistence.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [CVE-2026-25089](https://nvd.nist.gov/vuln/detail/CVE-2026-25089) in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Fortinet FortiSandbox `5.0.0` through `5.0.5`, `4.4.0` through `4.4.8`, `4.2` all versions, FortiSandbox Cloud/PaaS `5.0.4` through `5.0.5` | Crafted HTTP requests can reach OS command construction | Scope exposed FortiSandbox management routes and prove command-wrapper control only with inert lab markers. |
| [CVE-2026-39808](https://nvd.nist.gov/vuln/detail/CVE-2026-39808) in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Fortinet FortiSandbox `4.4.0` through `4.4.8` | Crafted input can execute unauthorized commands through a FortiSandbox HTTP path | Treat legacy `4.4.x` appliances as high-value perimeter and management-plane validation targets when in scope. |

The same scan observed GitHub Advisory updates for Axios `NO_PROXY` IPv4-mapped IPv6 handling and Go `x/crypto/ssh` certificate/agent constraints. Those workflows were already covered in existing Skillz pages, so this run did not duplicate them.

## Replayable validation boundaries

### FortiSandbox HTTP command-wrapper check

1. Confirm written authorization, product ownership, source IPs, and whether command execution is permitted. If command execution is not explicitly authorized, stop at route/version/authorization evidence.
2. Identify the product family and affected range from non-sensitive UI, API, banner, or asset-inventory evidence:
   - FortiSandbox `5.0.0` through `5.0.5`;
   - FortiSandbox `4.4.0` through `4.4.8`;
   - FortiSandbox `4.2` all versions;
   - FortiSandbox Cloud/PaaS `5.0.4` through `5.0.5` for CVE-2026-25089.
3. Map exposed HTTP management routes from approved source IPs only. Record whether each route is externally reachable, VPN-only, management-subnet-only, pre-authenticated, authenticated, or role-restricted.
4. In a lab or approved clone, exercise only inert command-wrapper control, such as a command that writes a known marker string under a disposable temp path or to a lab-only log sink.
5. Add controls for unaffected versions, blocked source networks, unauthenticated versus authenticated sessions, low-privilege versus admin roles, and routes that parse the same parameter shape but do not reach command construction.
6. In production/customer environments, avoid command execution unless written scope allows it. If allowed, use a command with no network egress, no persistence, no shell startup-file writes, no sample-queue changes, and immediate cleanup.

Report this as **FortiSandbox HTTP management input -> command-wrapper construction -> marker-only command execution in affected range**. Evidence should include product/version, route decision table, network exposure, auth preconditions, marker-only result, cleanup notes, and source links. Do not include reusable payload syntax.

## Operator checklist

- [ ] Is FortiSandbox reachable from the internet, partner networks, VPN pools, or only a dedicated management subnet?
- [ ] Does the target fall into the CVE-2026-25089 or CVE-2026-39808 affected version ranges?
- [ ] Which HTTP route family accepts the suspect parameter, and is it pre-auth or role-gated?
- [ ] Does a low-privilege appliance role reach the same command-wrapper path as admin?
- [ ] Can the command proof be reduced to a marker-only lab action without network egress or persistence?
- [ ] Is there a patched or non-affected negative control showing the route no longer reaches command construction?

## Reporting notes

- Lead with route and management-plane exposure, not payload detail.
- Separate confirmed source facts from lab observations. The public sources identify affected product ranges and OS command-injection impact; endpoint-specific behavior should come from the authorized lab.
- Redact appliance hostnames, serial numbers, customer sample names, malware-analysis artifacts, local network ranges, auth cookies, and screenshots that reveal submitted files.
- Pair this with broader appliance perimeter checks: management ACLs, VPN-only assumptions, role separation, and evidence that exploit validation stayed within the approved maintenance window.
