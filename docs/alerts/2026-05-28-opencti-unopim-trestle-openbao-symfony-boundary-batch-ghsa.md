# OpenCTI, UnoPim, compliance-trestle, OpenBao, and Symfony boundary batch (GHSA, 2026-05-28)

**Signal:** GitHub Advisory Database published a second May 28 batch with reusable offensive-operator value across control-plane authorization, admin upload handlers, local-import trust boundaries, tenant secret leases, and unsigned webhook callbacks. The durable lesson is to test where a privileged helper trusts caller-controlled object relationships, file paths, file extensions, lease identifiers, or provider event payloads.

Promoted items:

- `GHSA-q537-qhj4-wcjx` / `CVE-2026-44730`: OpenCTI / `pycti` `< 6.9.7` lets an organization admin abuse the GraphQL `userEdit` `relationAdd` path to add a higher-privileged user from another organization into their own organization, escalating toward full platform access.
- `GHSA-v22v-xwh7-2vrm` / `CVE-2025-55743`: UnoPim `<= 0.2.0` user-create profile image upload only enforces file type client-side, allowing an authenticated dashboard user to upload a server-executed PHP file under `/storage/admins/...`.
- `GHSA-4q5v-7g7x-j79w` / `CVE-2026-46345`: compliance-trestle `trestle author jinja -o` accepts `../`, `..\`, and absolute output paths, enabling arbitrary file write outside the trestle workspace.
- `GHSA-mj4x-vf5c-5xg8` / `CVE-2026-45774`: compliance-trestle profile import resolves `trestle://` and relative `imports[].href` / `back_matter.rlinks` paths without a workspace boundary check, enabling arbitrary file read when a victim imports attacker-controlled OSCAL YAML.
- `GHSA-v8v8-cm84-m686` / `CVE-2026-45808`: OpenBao `<= 2.5.3` legacy `sys/revoke` / `sys/renew` paths can act on intentionally leaked cross-namespace lease identifiers despite namespace ACL separation.
- `GHSA-59f3-vp2f-mp9w` / `CVE-2026-45755` and `GHSA-64hg-93w9-fc35` / `CVE-2026-45754`: Symfony Mailtrap, Mailjet, and LOX24 webhook parsers decode callback payloads without enforcing the configured HMAC, Basic-auth secret, or token, enabling forged delivery / bounce / click / SMS events.

Use this only in authorized tests. Keep proofs minimal: use lab tenants, disposable admin users, inert marker files, non-sensitive local files, tester-owned leases, and non-production webhook endpoints. Do not upload shells, read secrets, revoke real credentials, or corrupt production suppression lists unless the engagement explicitly provides a safe test harness.

## Operator checklist

### 1. OpenCTI GraphQL organization-admin privilege boundary

Where to look:

- OpenCTI deployments and automation using `pycti` before `6.9.7`.
- Multi-organization instances where some users are organization admins but not platform administrators.
- GraphQL API access paths that expose user relationship mutation to organization-scoped admins.

Safe validation path:

1. Confirm version evidence from UI metadata, container tags, package locks, SBOMs, or API responses.
2. Create or request two disposable organizations in a lab or scoped test tenant: one low-privileged organization admin and one higher-privileged user in another organization.
3. As the low-privileged organization admin, attempt only the relationship mutation needed to add the higher-privileged test user to the attacker's organization.
4. Verify whether the API accepts the cross-organization `relationAdd` and whether the low-privileged admin inherits access they could not reach before.
5. Roll back the relationship immediately. Do not target real analysts, production intelligence collections, or privileged service accounts.

Evidence to capture:

- Version / package evidence and caller role.
- The exact GraphQL mutation shape with test IDs redacted or sanitized.
- Before/after organization membership and authorization proof.
- A negative control showing the same caller could not directly access the privileged data before the relation mutation.

Reporting heuristic: strong reports prove **organization-scoped admin rights plus a cross-organization relationship mutation plus access to data or actions outside the caller's original organization**.

### 2. UnoPim authenticated profile-image upload to server-side execution

Where to look:

- UnoPim `<= 0.2.0` admin panels.
- User creation and profile image update flows under `/admin/settings/users/create` and adjacent dashboard account-management routes.
- Deployments that serve uploaded admin profile files from executable PHP paths such as `/storage/admins/<id>/...`.

Safe validation path:

1. Confirm the product/version and that the test account is allowed to create or edit a user profile image.
2. Upload a normal image once and capture the multipart request.
3. Replay in a lab or explicit test instance with a harmless PHP marker filename and content that only prints a fixed string, for example a single `echo` statement. Do not use command execution, reverse shells, or credential access payloads.
4. Request the uploaded file URL and verify whether the server executes PHP or serves the file as static text/download.
5. Delete the test user and uploaded file after capture.

Evidence to capture:

- Version and authenticated role needed for the upload.
- Multipart field name, filename extension change, and server response path.
- HTTP response proving server-side execution of a benign marker.
- Whether the upload directory is web-accessible and executable in the target deployment.

Reporting heuristic: distinguish **file upload bypass** from **actual code execution**. The high-impact proof is upload of a non-image extension followed by server-side interpretation from the returned storage path.

### 3. compliance-trestle workspace escape: Jinja output file write

Where to look:

- Repositories or CI jobs that run compliance-trestle `trestle author jinja` on templates or arguments influenced by project files, issue comments, agent tasks, or generated pipeline inputs.
- Versions `>= 4.0.0, < 4.0.3` and `<= 3.12.1`.
- Automation that later executes written files, especially `.github/workflows/*.yml`, hooks, config files, or generated scripts.

Safe validation path:

1. Confirm the trestle version in lockfiles, CI logs, container images, or `trestle version` output.
2. In a disposable workspace, run `trestle author jinja` with a tester-controlled template and an output path that should remain under the workspace.
3. Use a harmless marker output target outside the workspace, not a workflow, hook, shell profile, or config file used by another process.
4. Verify the marker appears outside the trestle root, then remove it.
5. For CI findings, prove the attacker-controlled input can influence `-o` without writing a file that will execute.

Evidence to capture:

- Version and command invocation source.
- Workspace root, output argument, resolved path, and created marker.
- The trust path from attacker-controlled project content or pipeline input to the command argument.
- Any follow-on execution path, documented as potential unless safely proven in an isolated CI clone.

Reporting heuristic: prioritize this when file write can cross from data generation into build control, CI configuration, or agent-executed files. A purely local self-write is lower signal unless a victim automation consumes attacker-controlled arguments.

### 4. compliance-trestle profile import arbitrary file read

Where to look:

- Automation importing third-party or contributor-supplied OSCAL profiles with compliance-trestle.
- `imports[].href` values using `trestle://...`, relative paths, or `back_matter.rlinks` in profile YAML.
- Versions `>= 4.0.0, <= 4.0.2` and `< 3.12.2`.

Safe validation path:

1. Confirm version evidence and identify the profile-import path.
2. Build a minimal OSCAL profile YAML in a lab that references a non-sensitive marker file outside the trestle workspace using both `trestle://../...` and relative traversal variants.
3. Trigger the same import or resolve command the target automation uses.
4. Verify whether the imported result includes or fetches content from the out-of-workspace marker file.
5. Do not target `/etc/passwd`, cloud credentials, SSH keys, or application secrets in production.

Evidence to capture:

- Version, import command, and attacker-controlled YAML field.
- The traversal variant and resolved file path.
- Proof that the import read a non-sensitive marker outside the workspace.
- Whether the result is logged, cached, committed, uploaded, or exposed through another interface.

Reporting heuristic: the strongest reports show **untrusted OSCAL input plus victim-side import plus read of a file outside the declared workspace**, especially when the imported content is stored in build artifacts or review output.

### 5. OpenBao cross-namespace lease revoke / renew boundary

Where to look:

- OpenBao `<= 2.5.3` deployments using namespaces for tenant isolation.
- Workflows that expose or allow tenants to intentionally disclose lease identifiers.
- API gateways or clients that still permit legacy `sys/revoke` or `sys/renew` endpoints.

Safe validation path:

1. Confirm the OpenBao version and namespace model in a lab or explicitly scoped tenant environment.
2. Create two disposable namespaces and issue a short-lived, harmless dynamic credential or secret lease in the victim namespace.
3. Intentionally share only that test lease ID with a user in another namespace.
4. From the other namespace, call the legacy revoke or renew path for the test lease ID.
5. Verify whether the lease state changes across the namespace boundary, then clean up both test namespaces.

Evidence to capture:

- Version, namespaces, caller policies, and endpoint path.
- Lease ID format with sensitive values redacted.
- Before/after lease state showing cross-namespace action.
- Confirmation that normal namespace ACLs should have denied equivalent access.

Reporting heuristic: frame this as **cross-tenant lease lifecycle control when an identifier is disclosed**, not broad secret read. Impact is strongest when lease IDs are exposed in logs, tickets, job output, or shared automation artifacts.

### 6. Symfony provider webhook parser signature/secret bypass

Where to look:

- Symfony apps using Mailtrap, Mailjet, or LOX24 bridges and exposing provider callback endpoints.
- Versions in these vulnerable ranges: `symfony/mailtrap-mailer >= 7.2.0, < 7.4.12` or `>= 8.0.0, < 8.0.12`; `symfony/mailjet-mailer >= 6.4.0, < 6.4.40`, `>= 7.0.0, < 7.4.12`, or `>= 8.0.0, < 8.0.12`; `symfony/lox24-notifier >= 7.1.0, < 7.4.12` or `>= 8.0.0, < 8.0.12`; and corresponding `symfony/symfony` metapackage versions.
- Business logic that updates suppression lists, delivery status, customer messaging state, billing events, or analytics from webhook callbacks.

Safe validation path:

1. Confirm package versions and identify a non-production webhook endpoint or tester-owned tenant.
2. Send a forged provider-shaped event without the expected signature, Basic-auth credential, or token header.
3. Use a harmless recipient/event marker and avoid real customer addresses.
4. Verify whether the application accepts and processes the event despite a configured secret.
5. Check whether downstream state changes are limited to metrics or can suppress delivery, trigger workflows, or mark security-sensitive messages as delivered/opened.

Evidence to capture:

- Package/version evidence and provider bridge in use.
- Endpoint path, missing/invalid authentication header, and accepted response.
- Before/after application state for the harmless event marker.
- The configured secret expectation, if available, without disclosing the secret value.

Reporting heuristic: high-signal reports connect **unsigned callback acceptance** to a concrete downstream action: suppression-list modification, fraud in delivery metrics, message-state manipulation, or workflow trigger bypass.

## Non-signal this hour

Reviewed but not promoted as standalone Skillz guidance:

- `GHSA-q8cj-789h-vg24` / `CVE-2026-46358` OpenBao inline-auth audit-log header redaction failure. Useful for post-compromise secret hygiene, but it requires access to the audit device and does not add a standalone operator validation workflow here.
- `GHSA-8v8v-g73j-492j` / `CVE-2026-45756` Symfony JsonPath `match()` / `search()` ReDoS. Availability-only and already covered by generic parser/resource-boundary methodology.
- `GHSA-995v-fvrw-c78m` / `CVE-2026-45287` OpenTelemetry Go schema `ParseFile` file-descriptor leak. Low-signal availability issue requiring repeated attacker-influenced schema parsing.
- CISA KEV stayed catalog `2026.05.28`; top entries remained Nx Console, TanStack, Daemon Tools Lite, LiteSpeed, Drupal, Langflow, and Trend Micro entries already reflected or triaged.
- PortSwigger Research stayed on Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis article.
- ProjectDiscovery `/blog/rss` stayed on already-covered Neo / Nuclei / DAST material.
- GitHub Security Blog stayed GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [OpenCTI GraphQL privilege escalation advisory (`GHSA-q537-qhj4-wcjx`)](https://github.com/advisories/GHSA-q537-qhj4-wcjx)
- [UnoPim arbitrary file upload to RCE advisory (`GHSA-v22v-xwh7-2vrm`)](https://github.com/advisories/GHSA-v22v-xwh7-2vrm)
- [compliance-trestle Jinja arbitrary file write advisory (`GHSA-4q5v-7g7x-j79w`)](https://github.com/advisories/GHSA-4q5v-7g7x-j79w)
- [compliance-trestle profile import arbitrary file read advisory (`GHSA-mj4x-vf5c-5xg8`)](https://github.com/advisories/GHSA-mj4x-vf5c-5xg8)
- [OpenBao cross-namespace lease revocation advisory (`GHSA-v8v8-cm84-m686`)](https://github.com/advisories/GHSA-v8v8-cm84-m686)
- [Symfony Mailtrap webhook signature advisory (`GHSA-59f3-vp2f-mp9w`)](https://github.com/advisories/GHSA-59f3-vp2f-mp9w)
- [Symfony Mailjet / LOX24 webhook secret advisory (`GHSA-64hg-93w9-fc35`)](https://github.com/advisories/GHSA-64hg-93w9-fc35)
