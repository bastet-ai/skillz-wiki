# VeloCloud Orchestrator internal-function command boundary checks

Sources: hourly offensive-security scan, 2026-07-27; Arista [Security Advisory 0144](https://www.arista.com/en/support/advisories-notices/security-advisory/24364-security-advisory-0144); [CVE-2026-16812](https://nvd.nist.gov/vuln/detail/CVE-2026-16812); [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-16812); and [GHSA-f2cp-q2qv-6563](https://github.com/advisories/GHSA-f2cp-q2qv-6563).

This KEV addition is durable for operators because it exposes a reusable appliance control-plane failure: functionality intended for internal use is remotely reachable through the VeloCloud Orchestrator (VCO) web interface and crosses into an OS command boundary without tenant or operator credentials. The useful assessment is product ownership, web-interface reachability, affected-version state, route/auth classification, and—only in an isolated lab—an inert marker proving the internal-function-to-host-command edge. Public sources do not identify the vulnerable endpoint or parameter, so do not invent or spray candidate payloads.

!!! warning "Authorized validation only"
    Restrict testing to owned VCO labs or explicit customer-approved windows. On production appliances, stop at exposure, version, and authorization evidence unless the owner separately approves command execution. Never publish a working payload, retrieve VCO databases/configuration/credentials/certificates, alter managed Edge devices, create accounts or persistence, or use callbacks to production/internal services.

## Confirmed source facts

| Item | Confirmed detail | Operator value |
| --- | --- | --- |
| Boundary | Arista says functionality intended only for internal use is remotely accessible and can impact the VCO host. The CVE class is CWE-78 OS command injection. | Treat “internal” appliance handlers as externally testable authorization and command-construction boundaries; do not assume an internal route name implies network isolation. |
| Preconditions | Network access to the VCO web interface is required. VCO tenant and operator credentials are not required. Arista says VCO is exposed by default and no VCO configuration prevents the exposure. | Build an anonymous-versus-authenticated route matrix from approved source networks before attempting any command proof. |
| Exploitation state | Arista says the issue is actively exploited; CISA added it to KEV on 2026-07-27. | Prioritize explicitly in-scope on-prem VCO interfaces, but do not turn active exploitation into permission for production payload testing. |
| Affected product | VeloCloud Orchestrator On-Prem, formerly VeloCloud Orchestrator by Broadcom. Hosted and Dedicated VCO are listed as unaffected because they were patched before disclosure. VeloCloud Gateway and Edge are not the vulnerable product. | Prevent false positives caused by matching the broader VeloCloud product name or an Edge/Gateway banner. |
| Affected ranges | `5.2.x < 5.2.3.14`, `6.1.x < 6.1.3.4`, `6.4.x < 6.4.2.4`, and `7.0.x < 7.0.0.1`. End-of-support releases were not assessed. | Require exact train/build evidence; do not infer safety for an unassessed EOL release. |
| Fixed-release presentation | Arista’s affected-software section identifies `7.0.0.1` as the `7.0.x` threshold, while the advisory’s resolution list currently names `5.2.3.14`, `6.1.3.4`, and `6.4.2.4`. | Record this source discrepancy and obtain owner/vendor confirmation before reporting a `7.0.x` target as fixed. |
| Blast radius | Arista says compromise can affect the orchestrator host and managed data and may provide access to VeloCloud Edge devices. | Report the orchestrator-to-managed-edge control-plane relationship without exercising it; never use a command-boundary proof to pivot to managed devices. |

## Scope and prerequisites

Before testing, collect:

- written authorization naming the VCO host, source IPs, test window, and whether command execution is allowed;
- evidence that the target is **VCO On-Prem**, not Hosted, Dedicated, Gateway, Edge, or an unrelated Arista product;
- an exact release train and build from owner inventory or a non-sensitive authenticated administrative view;
- the web-interface exposure path: internet, partner network, VPN, management VLAN, or local lab;
- an isolated VCO lab or approved clone if marker-only command execution will be attempted;
- a disposable marker path and cleanup plan that cannot affect VCO configuration, databases, packages, services, logs, backups, or managed Edge state.

## Replayable operator workflow

### 1. Establish product ownership without broad probing

1. Start with asset inventory, DNS, TLS certificate metadata, approved HTTP service discovery, and owner-provided deployment records.
2. Distinguish VCO On-Prem from Hosted/Dedicated and from Gateway/Edge products. Preserve the evidence used for that classification.
3. Record web-interface reachability from each explicitly approved network position. A timeout from the public internet is not proof that VPN or partner paths are safe.
4. Avoid relying on favicon or page-title matches alone; shared branding can identify the product family but not the affected deployment model or build.

### 2. Build a version decision table

| Observed release | Source-backed disposition |
| --- | --- |
| `5.2.x` before `5.2.3.14` | Affected |
| `6.1.x` before `6.1.3.4` | Affected |
| `6.4.x` before `6.4.2.4` | Affected |
| `7.0.x` before `7.0.0.1` | Affected |
| At or above a listed threshold | Patched-range candidate; confirm exact train/build and route behavior |
| End-of-support or unknown train | Unassessed; do not label vulnerable or safe from version inference alone |
| Hosted/Dedicated VCO | Vendor lists as already patched; verify deployment ownership rather than testing the on-prem command path |

Capture the source and timestamp for version evidence. If the build cannot be established non-destructively, report **reachable on-prem VCO with unknown build** rather than asserting CVE exposure.

### 3. Classify route and authentication behavior

Public sources intentionally do not name the vulnerable endpoint. In an owned lab or with vendor/customer-provided request evidence:

1. Inventory only documented or application-referenced web route families; do not brute-force large route dictionaries against a live orchestrator.
2. Replay benign baseline requests as anonymous, tenant, operator, and administrator actors where those roles are available.
3. Record response status, redirect chain, content type, body length/hash, and whether any privileged backend action begins.
4. Treat a route as interesting when anonymous network input reaches behavior reserved for internal maintenance, but do not equate a `200`, `500`, or timing difference with command execution.
5. Compare a vulnerable lab build with a fixed build. The strongest negative control is rejection before privileged internal functionality or command construction.

A useful decision table is:

| Network position | Actor | Route class | Vulnerable build | Fixed build | Backend effect |
| --- | --- | --- | --- | --- | --- |
| Approved external/VPN source | Anonymous | Internal-function candidate | Record observed status/hash | Record observed status/hash | None, route reached, or inert marker |
| Management network | Tenant/operator | Same route | Record | Record | Record |
| Management network | Admin | Documented equivalent | Record | Record | Expected administrative control |

### 4. Prove the command edge only in an isolated lab

If written scope explicitly permits command execution:

1. Use a disposable VCO instance with no production Edge registrations, credentials, certificates, databases, or customer data.
2. Instrument the command wrapper or use a marker-only action confined to a pre-created temporary directory. Prefer an execution counter or mocked sink over a real shell.
3. Use a unique marker with no command output, network egress, persistence, service changes, package installation, account changes, or privilege escalation.
4. Demonstrate the edges separately:
   - anonymous request reaches the internal-only function;
   - one controlled field reaches command construction;
   - the inert marker occurs on an affected build;
   - the same request is rejected or safely bound on a fixed build.
5. Remove the marker and preserve only redacted request metadata, hashes, instrumentation output, and the fixed-version comparison.

Do not publish endpoint names or parameter/payload syntax if doing so would provide a turnkey exploit for an actively exploited unauthenticated appliance issue.

## Stop conditions

Stop immediately when:

- the target is production and command execution was not expressly approved;
- product/build ownership cannot distinguish On-Prem VCO from unaffected product forms;
- a request returns configuration, database, credential, certificate, device-inventory, backup, or customer data;
- the test would contact a managed Edge, internal service, metadata endpoint, or third-party callback;
- unexpected command execution, file creation, administrator activity, or outbound traffic appears;
- the appliance shows signs of prior compromise—preserve evidence and hand control back to the owner rather than continuing exploit validation.

## Evidence and reporting heuristic

A strong report contains:

- exact VCO deployment model, release train/build, and version-evidence source;
- approved network position and anonymous/authenticated actor state;
- route class and the expected **external web request -> internal-only function -> host command** boundary;
- baseline, affected-build, fixed-build, and denied-network decision rows;
- marker-only proof details and cleanup, if separately authorized;
- explicit separation between vendor-confirmed facts and lab-observed endpoint behavior;
- blast-radius context limited to the orchestrator control plane and potential managed-Edge reach—without exercising that pivot.

Suggested title: `Anonymous VCO web request reaches internal-only host command boundary on affected on-prem build`.

Do not claim RCE from version presence, route reachability, a server error, or a timing change alone. Conversely, do not require production command execution when product ownership, an affected build, anonymous route reachability, and a faithful lab/fixed-build reproduction already establish the boundary safely.

## October 22 follow-up: second VCO advisory — any authenticated user upgrades to local "superuser operator"

[GHSA-964w-6mm5-rm95](https://github.com/advisories/GHSA-964w-6mm5-rm95) / CVE-2026-114625 (critical, CVSS 9.9 AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, published 2026-10-22) is the second GHSA on this same product surface. Confirmed vendor facts: on affected **on-prem** VCO, **any authenticated user** can gain operator privileges and **masquerade as the local "superuser operator" user**, including access to functionality "intended for internal use only and which is not intended to be remotely accessible"; hosted/Dedicated VCO were already patched (deployment-model split holds again — treat a hosted tenant as out of scope and an on-prem instance as the target). The advisory withholds endpoint detail; do not invent or spray candidates.

Operator value beyond the first advisory:

- **Second boundary, different precondition.** CVE-2026-16812 was anonymous → command boundary; this one is **low-privilege authenticated → superuser-operator vertical escalation**. On SD-WAN orchestrators, run the authenticated-user battery (tenant user, read-only operator, support account) against every admin/console route family — appliance UIs frequently gate menus client-side while the backend branches on a caller-supplied role/tenant field. The vertical-ladder probe (low-priv session reaching an internal-role behavior) is now a second independent axis on this exact product; same-product re-sweep keeps paying.
- **"Masquerades as a local superuser operator" is an identity-binding failure, not just a permission bit.** When escalation lands on a *named local/system account*, check whether the impersonated identity's own credentials/secrets/certificates become readable afterward — appliance local accounts often hold orchestrator-to-Edge control-plane authority (the same managed-Edge blast radius the first advisory warned about). Report the ladder; never exercise the Edge pivot.
- **Deployment-model fingerprint first, both advisories share it:** on-prem = target, hosted/dedicated = vendor-patched. Keep the same version decision table, and note a fixed build for the command-injection ranges does not close the 9.9 escalation if the escalation ranges differ — require per-advisory band evidence, not one build check.
