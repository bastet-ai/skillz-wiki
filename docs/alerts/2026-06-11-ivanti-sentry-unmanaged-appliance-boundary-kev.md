# Ivanti Sentry unmanaged-appliance command boundary

Source: hourly offensive-security scan, 2026-06-11. Primary entries: CISA KEV [CVE-2026-10520](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), Ivanti's advisory [Security Advisory Ivanti Sentry CVE-2026-10520 CVE-2026-10523](https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-10520-CVE-2026-10523?language=en_US), and NVD records for [CVE-2026-10520](https://nvd.nist.gov/vuln/detail/CVE-2026-10520) and [CVE-2026-10523](https://nvd.nist.gov/vuln/detail/CVE-2026-10523).

This is durable for operators because it turns a perimeter mobile-device-management appliance advisory into a repeatable boundary check: identify Ivanti Sentry appliances, separate managed from unmanaged deployments, verify whether externally reachable endpoints are exposed, and keep any validation to customer-approved canaries instead of live command execution.

## What changed

- **CISA added CVE-2026-10520 to KEV on 2026-06-11** for active exploitation of Ivanti Sentry OS command injection.
- **Affected product:** Ivanti Sentry, formerly MobileIron Sentry.
- **Command boundary:** NVD describes CVE-2026-10520 as OS command injection in Ivanti Sentry before `R10.5.2`, `R10.6.2`, and `R10.7.1`, allowing a remote unauthenticated user to achieve root-level remote code execution.
- **Deployment precondition:** CISA states exploitation succeeds where the Sentry appliance is in an **unmanaged state** and its endpoints are externally reachable. CISA also notes that mTLS with EPMM or restricted HTTPS access through Neurons for MDM makes interfaces inaccessible to external actors.
- **Adjacent advisory context:** NVD describes CVE-2026-10523 as an authentication bypass in the same affected version bands that allows a remote unauthenticated attacker to create arbitrary administrative accounts and obtain full administrative access. Treat it as the same appliance-management trust boundary unless a target-specific advisory splits scope differently.

## Operator triage

1. **Confirm ownership and product identity.** Use scope records, customer inventory, DNS names, certificates, branding, and ASN context before probing. Mobile-management gateways often sit close to sensitive device and mail infrastructure.
2. **Map externally reachable Sentry surfaces.** Prioritize internet-facing HTTPS endpoints and any management, enrollment, or gateway paths associated with Ivanti Sentry / MobileIron Sentry.
3. **Classify managed vs unmanaged state.** The key public exploitability clue is an unmanaged Sentry appliance with reachable endpoints. Ask the customer for deployment state if it is not safely inferable from inventory or banner evidence.
4. **Check compensating access boundaries without bypassing them.** Record whether mTLS to EPMM, Neurons for MDM restricted HTTPS access, VPN-only access, IP allowlists, or private routing prevents unauthenticated external reachability.
5. **Avoid production exploit attempts.** Do not run OS-command payloads, create administrator accounts, or collect appliance secrets. If validation beyond reachability is needed, use a lab clone or a named customer-approved test window with disposable canary material.

## Safe recon patterns

Use low-impact discovery only against explicitly scoped assets:

```bash
# Resolve candidate Ivanti/MobileIron Sentry hostnames supplied by scope or inventory.
dnsx -l sentry-hosts.txt -a -aaaa -resp -o sentry-dns.txt

# Fingerprint HTTPS surfaces without sending exploit payloads.
httpx -l sentry-hosts.txt -title -tech-detect -status-code -location -tls-probe -follow-redirects -o sentry-httpx.txt

# Confirm exposed web ports and preserve timing/source evidence for the report.
nmap -sT -Pn -p 443,8443,9443 --open --reason -oA ivanti-sentry-web scoped-sentry-targets.txt
```

Evidence worth keeping: scoped hostname/IP, certificate subject/SANs, product branding or inventory proof, reachable ports, HTTP status/title evidence, whether external access requires mTLS or restricted routing, the stated deployment state, and the tested source IP. Keep real device identifiers, user data, certificates, session cookies, and appliance configuration out of public artifacts.

## Replayable validation boundary

### Minimum proof for a pentest or bug-bounty report

- Show the asset is an in-scope Ivanti Sentry / MobileIron Sentry appliance.
- Show the affected version band or customer-confirmed exposure to CVE-2026-10520/CVE-2026-10523.
- Show whether unauthenticated external clients can reach the relevant appliance endpoints.
- Show whether the appliance is unmanaged or otherwise lacks the mTLS/restricted-access conditions described by CISA.
- If exploit validation is approved, perform it only in a lab or with vendor/customer-provided canary procedures. The proof should demonstrate boundary crossing with a harmless marker, not command execution against production or real admin-account creation.

### Strong negative controls

- Sentry appliance is reachable only through mTLS-bound EPMM or restricted Neurons for MDM access.
- HTTPS management/enrollment endpoints are private, VPN-only, or IP-restricted from the tester's external source.
- Customer inventory confirms the appliance is managed and not in the unmanaged state called out by CISA.
- Version evidence shows `R10.5.2`, `R10.6.2`, `R10.7.1`, or later, with no exposed vulnerable endpoint path.

### Report fields

- Asset and authorization reference.
- Product proof and version/deployment-state evidence.
- External reachability evidence, including tester source IP and timestamp.
- Whether mTLS, Neurons restricted HTTPS, VPN-only access, or IP restrictions blocked unauthenticated reachability.
- Whether validation stopped at recon, lab canary execution, or customer-approved production canary.
- Explicit statement that no real OS commands, administrator-account creation, credential access, or device-data access was attempted unless separately authorized and documented.

## Safety notes

- Do not test unauthenticated RCE or admin-account creation against third-party Sentry appliances without explicit written authorization.
- Do not publish payloads, endpoint paths, appliance secrets, device identifiers, or session material.
- Do not pivot from a reachable Sentry appliance into EPMM, Neurons for MDM, mail, or internal device networks unless the rules of engagement explicitly authorize that follow-on phase.
- Preserve only the minimum boundary evidence needed for the report; redact hostnames or tenant identifiers when the engagement requires it.
