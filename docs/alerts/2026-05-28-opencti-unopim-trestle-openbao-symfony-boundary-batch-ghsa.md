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

### 4b. compliance-trestle Jinja2 re-parsing SSTI — untrusted data executed as template source (August 28)

**Advisory (2026-08-28 GitHub wave):** [GHSA-jw39-3688-r4rx / CVE-2026-54757](https://github.com/advisories/GHSA-jw39-3688-r4rx) — high, SSTI → RCE.

Different boundary from the file-read item above: here untrusted **data** is re-parsed as **Jinja2 template source** without a sandbox. The root anti-pattern is passing runtime data — markdown file content, extracted section text, or LUT/data-field values — into `Parser(self.environment, content).parse()` using a plain `jinja2.Environment` (not `SandboxedEnvironment`), so `{{ ... }}` payloads execute and can traverse `__class__.__mro__` / `__globals__` / `__subclasses__()` to reach `os.system` / `subprocess`.

Where to look:

- `MDCleanInclude.parse()` and `MDSectionInclude.parse()` in `trestle/core/jinja/tags.py` — markdown bodies / section `raw_text` loaded via `FileSystemLoader.get_source()` then fed straight to `Parser(...).parse()`.
- Any pipeline rendering third-party or vendor-supplied SSP documents, LUT YAML, or markdown includes into trusted templates, where rendered output or data-field values flow back into a re-parsing step.
- Note the previously-fixed `render_template()` recursive `while` loop (single `template.render(**lut)` now) — the same `__globals__.os.system()` technique survives in the remaining tag re-parsing paths.

Safe validation path:

1. Confirm the tag handlers in use (`md_clean_include`, `mdsection_include`) and that the trestle workspace is writable in the lab.
2. Place a marker markdown file whose body contains a **benign** Jinja2 construct that prints a canary (e.g. `{{ 7*6 }}`), plus a disabled/commented object-traversal line.
3. Trigger the trestle `author jinja` render over it and confirm the canary evaluates in the output — proving the markdown body was executed as template source, not emitted as text.
4. In a sandboxed lab with a denied process sink, replace the traversal sink with a recorder that logs the argument and returns a fixed string; capture the recorded argument as the RCE-boundary proof.
5. Do not render real vendor/compliance data, do not reach internal endpoints, and do not execute discovery or persistence commands.

Evidence to capture:

- The exact `Parser(self.environment, ...)` sink line and the `Environment` (non-sandboxed) construction site.
- The canary-evaluates differential vs. a sandboxed/escaped control.
- The input-to-parse-to-execute path for each affected tag (`MDCleanInclude`, `MDSectionInclude`), noting `MDDatestamp` as the lower-risk internally-generated-string variant.

Reporting heuristic: the strongest reports connect **attacker-writable workspace/data content** to a **secondary `Parser.parse()` on a non-sandboxed `Environment`**, and enumerate *every* re-parsing call site (the fix that removed the `render_template` loop is not sufficient because the tags re-parse independently).

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

## September 22 follow-up: OpenBao triple — recovery-mode token timing leak, templated-policy wildcard escalation, LIST skips deny policies (3 GHSAs, surfaced via the Sept 22 GHSA sync)

OpenBao (the Vault fork) keeps showing up on this page; the July-published, Sept-22-synced trio adds three reusable secret-store axes:

- **Recovery-mode unconstant-time token comparison** (CVE-2026-63132, [GHSA-34fc-gh42-pj53](https://github.com/advisories/GHSA-34fc-gh42-pj53), critical): the highly privileged recovery mode compared the single recovery token in a way leakable via **timing attack** — byte-by-byte extraction of the token that unlocks read/write over the whole store. Sweep rule: every *break-glass* authentication surface (recovery/unseal/root-token flows) deserves the constant-time assumption test; the recovery path is rarely built with the same care as the main auth path, and it is the highest-value credential on the system. Lab-bounded: your own disposable sealed instance, measure per-position latency deltas on rejected tokens, extract only a synthetic token you planted.
- **Templated ACL policies + attacker-influenced identity fields = glob injection** (CVE-2026-71543, [GHSA-59w7-v8rr-pr4p](https://github.com/advisories/GHSA-59w7-v8rr-pr4p), high): policies like `data/{{identity.entity.aliases.<mount>.name}}/*` substitute the **username** at evaluation time; if username selection allows `*`, `+`, or `/`, a self-registration flow turns `alice/*` confinement into whole-engine access. Same shape in the **PKI** engine (`allowed_uri_sans_template`/`allowed_domains` — username `*` → `*.example.com` glob → issue certs for any subdomain) and **SSH** engine (`allowed_users`/`allowed_domains`). This is the template-substitution sibling of the wiki's wildcard-subject family (Open WebUI `%` subjects, Sept 15): **when any identity-derived field is interpolated into a glob-capable policy, the field's validation charset is the privilege boundary.** Bug-hunt rule: on any secrets/identity platform with self-service signup, register a username containing `*`, `+`, `/` and diff what your token can read — same test for cert/SSH principal fields.
- **LIST operations skip stricter deny policies** (CVE-2026-63131, [GHSA-xp3c-3jw3-4vcr](https://github.com/advisories/GHSA-xp3c-3jw3-4vcr)): path denials enforced on read/write were not applied to the LIST verb — enumeration survives where access is denied. Joins the count-query-oracle and verb-matrix family (MISP POST/PUT-only login, Airflow count filter): build the **verb × policy decision table**, include LIST/HEAD/OPTIONS, and treat list endpoints as disclosure channels even when every direct read is denied.
- Same-wave, tracked not promoted: OpenBao Agent writing secrets to stdout (CVE-2026-77285) — local artifact-hygiene class, relevant to post-access hunting on build agents (secret runners that echo material into logs is a credential-harvest target, not a new attack axis).
