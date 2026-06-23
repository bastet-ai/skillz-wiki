# Snipe-IT, Mattermost, Camel K, Algernon, and Jackson boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entries: GitHub Advisory Database [GHSA-52fw-7fw2-fmv5](https://github.com/advisories/GHSA-52fw-7fw2-fmv5), [GHSA-f3c5-6cw8-fg57](https://github.com/advisories/GHSA-f3c5-6cw8-fg57), [GHSA-pwpj-p52h-q484](https://github.com/advisories/GHSA-pwpj-p52h-q484), [GHSA-hf68-g98v-wp9g](https://github.com/advisories/GHSA-hf68-g98v-wp9g), [GHSA-33g4-646g-qwmm](https://github.com/advisories/GHSA-33g4-646g-qwmm), [GHSA-p68w-rgmg-3c2v](https://github.com/advisories/GHSA-p68w-rgmg-3c2v), [GHSA-x667-r589-43m7](https://github.com/advisories/GHSA-x667-r589-43m7), [GHSA-6mmj-jhqj-6c6q](https://github.com/advisories/GHSA-6mmj-jhqj-6c6q), [GHSA-c4r7-j7pp-r8mp](https://github.com/advisories/GHSA-c4r7-j7pp-r8mp), [GHSA-6cfr-wp44-6qmv](https://github.com/advisories/GHSA-6cfr-wp44-6qmv), [GHSA-q8ch-jx67-q52x](https://github.com/advisories/GHSA-q8ch-jx67-q52x), [GHSA-jc3j-x6pg-4hmv](https://github.com/advisories/GHSA-jc3j-x6pg-4hmv), [GHSA-j3rv-43j4-c7qm](https://github.com/advisories/GHSA-j3rv-43j4-c7qm), [GHSA-rmj7-2vxq-3g9f](https://github.com/advisories/GHSA-rmj7-2vxq-3g9f), and [GHSA-hgj6-7826-r7m5](https://github.com/advisories/GHSA-hgj6-7826-r7m5).

These items are durable for operators because they share a reusable pattern: client-controlled identity, route, namespace, host, or type metadata crosses into a more privileged control plane. Validate with owned labs, disposable users, synthetic namespaces, inert files, and canary DNS names only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-52fw-7fw2-fmv5](https://github.com/advisories/GHSA-52fw-7fw2-fmv5) / CVE-2026-48493 | Snipe-IT API | a user with `users.edit` plus API access can update their own permission set beyond the intended role envelope | Test self-service user update routes for permission-field mass assignment and prove with harmless view-only capability toggles. |
| [GHSA-f3c5-6cw8-fg57](https://github.com/advisories/GHSA-f3c5-6cw8-fg57) / CVE-2026-48492 | Snipe-IT selectlist API | low-privileged authenticated users can enumerate user IDs and identity metadata from generic selectlist endpoints | Add inventory/asset apps to recon checklists for roleless API enumeration and user-ID harvesting that enables follow-on authorization tests. |
| [GHSA-pwpj-p52h-q484](https://github.com/advisories/GHSA-pwpj-p52h-q484) / CVE-2026-54329 | Snipe-IT Accessories API | FMCS tenant context can be overwritten by request-supplied `company_id` during accessory creation | Test multi-company APIs for mass-assigned tenant IDs using synthetic company records and harmless accessory markers. |
| [GHSA-hf68-g98v-wp9g](https://github.com/advisories/GHSA-hf68-g98v-wp9g) / CVE-2026-55483 | Snipe-IT user creation | `users.create` paths stripped `superuser` but not `admin` permission during web/API user creation | Check delegated HR/helpdesk roles that can create users for admin-flag field acceptance; prove with disposable accounts only. |
| [GHSA-33g4-646g-qwmm](https://github.com/advisories/GHSA-33g4-646g-qwmm) / CVE-2026-55482 | Snipe-IT bulk asset update | bulk asset updates accept `company_id` directly instead of deriving it from the current user | Add bulk update/import endpoints to tenant-boundary checks; evidence is a synthetic asset moving between lab companies. |
| [GHSA-p68w-rgmg-3c2v](https://github.com/advisories/GHSA-p68w-rgmg-3c2v) / CVE-2026-49976 | Snipe-IT CSV user import | import update mode rebuilds auth fields from raw CSV rows after attempted field stripping | Test importer update paths for email/username mutation of non-owned users with lab-only accounts and owned reset addresses. |
| [GHSA-x667-r589-43m7](https://github.com/advisories/GHSA-x667-r589-43m7) / CVE-2026-55519 | Snipe-IT asset file deletion | class-level asset edit authorization is used where instance/company-level ownership is required | Verify file-delete IDORs with disposable attachments; never delete real asset evidence or user uploads. |
| [GHSA-6mmj-jhqj-6c6q](https://github.com/advisories/GHSA-6mmj-jhqj-6c6q) / CVE-2026-55542 | Snipe-IT S3 signature image retrieval | S3-backed signature retrieval can return a temporary signed URL before the authorization check used by local files | Test only synthetic signature filenames and prove unauthorized signed-URL issuance without downloading sensitive files. |
| [GHSA-c4r7-j7pp-r8mp](https://github.com/advisories/GHSA-c4r7-j7pp-r8mp) / CVE-2026-4858 | Mattermost integration action URLs | an authenticated user-controlled integration URL path can traverse into arbitrary Mattermost API calls executed with a system-admin auth token | Validate webhook/action URL canonicalization with harmless status or synthetic team resources; do not perform destructive admin API calls. |
| [GHSA-6cfr-wp44-6qmv](https://github.com/advisories/GHSA-6cfr-wp44-6qmv) / CVE-2026-4055 | Mattermost playbook runs | create-run authorization is checked against one team while the request supplies a different target team ID | Reuse as an IDOR pattern: compare permission checks to every request-supplied tenant/team/resource identifier. |
| [GHSA-q8ch-jx67-q52x](https://github.com/advisories/GHSA-q8ch-jx67-q52x) / CVE-2026-45760 | Apache Camel K operator | namespace-authorized users can create `Build` resources that steer pod generation into another namespace, including the operator namespace | In Kubernetes reviews, test custom resources whose spec chooses namespace, service account, image, or pod template placement. |
| [GHSA-jc3j-x6pg-4hmv](https://github.com/advisories/GHSA-jc3j-x6pg-4hmv) / CVE-2026-48126 | Algernon `--domain` / `--letsencrypt` mode | raw `Host` header is joined into the served directory, so `..` can escape one level above the document root and render executable server-side files | Add host-header filesystem joins to web-server boundary testing; prove only with a parent-directory marker file or inert Lua marker in a lab. |
| [GHSA-j3rv-43j4-c7qm](https://github.com/advisories/GHSA-j3rv-43j4-c7qm) / CVE-2026-54512 | Jackson databind polymorphic typing | `PolymorphicTypeValidator` validates a generic container raw type but misses nested type parameters | For Java deserialization reviews, treat generic type IDs as a validator-bypass surface and prove with inert canary classes, not real gadgets. |
| [GHSA-rmj7-2vxq-3g9f](https://github.com/advisories/GHSA-rmj7-2vxq-3g9f) / CVE-2026-54513 | Jackson databind `allowIfSubTypeIsArray()` | array allowlisting validates only the array shape, not the component type | Add array-wrapped type IDs to Jackson PTV harnesses when testing allowlists. |
| [GHSA-hgj6-7826-r7m5](https://github.com/advisories/GHSA-hgj6-7826-r7m5) / CVE-2026-54514 | Jackson `InetSocketAddress` binding | deserialization performs eager DNS resolution before application validation or explicit connection logic | Use owned canary DNS names to detect outbound resolver interaction from JSON binding alone. |

Adjacent [GHSA-58fg-62fg-3fcj](https://github.com/advisories/GHSA-58fg-62fg-3fcj), [GHSA-r6fj-869h-4f6q](https://github.com/advisories/GHSA-r6fj-869h-4f6q), [GHSA-3fc8-8hp6-6jr4](https://github.com/advisories/GHSA-3fc8-8hp6-6jr4), [GHSA-5w46-g9pq-wh6f](https://github.com/advisories/GHSA-5w46-g9pq-wh6f), [GHSA-53h4-8rc4-f539](https://github.com/advisories/GHSA-53h4-8rc4-f539), [GHSA-mr8g-2mj4-pcq2](https://github.com/advisories/GHSA-mr8g-2mj4-pcq2), [GHSA-6x4j-8954-5hxm](https://github.com/advisories/GHSA-6x4j-8954-5hxm), [GHSA-5hh8-q8hv-fr38](https://github.com/advisories/GHSA-5hh8-q8hv-fr38), [GHSA-9fxm-vc8v-hj55](https://github.com/advisories/GHSA-9fxm-vc8v-hj55), [GHSA-5jmj-h7xm-6q6v](https://github.com/advisories/GHSA-5jmj-h7xm-6q6v), [GHSA-3wrr-7qpf-2prh](https://github.com/advisories/GHSA-3wrr-7qpf-2prh), and [GHSA-rcqc-6cw3-h962](https://github.com/advisories/GHSA-rcqc-6cw3-h962) were processed without standalone pages: they are either generic XSS/enumeration/crypto/resource notes, Snipe-IT second-factor control issues that do not add a new endpoint-boundary pattern beyond the table above, or narrower Jackson authorization edge cases that should be revisited if paired with a stronger exploit-chain workflow.

## Operator triage

1. **Start with privilege boundaries, not CVSS.** Prioritize routes where a low-privileged user supplies permission fields, tenant/team IDs, target namespaces, action URLs, hostnames, or type IDs.
2. **Build positive and negative role matrices.** For Snipe-IT and Mattermost, compare a no-permission user, a scoped editor, a team member, and an admin against the same endpoint.
3. **Keep Kubernetes checks synthetic.** For Camel K, use a disposable namespace, fake images, and inert pod templates; evidence is the generated resource placement decision, not workload execution.
4. **Constrain filesystem proofs.** For Algernon, create a disposable parent-directory canary and stop after proving one-level docroot escape or inert renderer invocation in a lab.
5. **Instrument Java harnesses.** For Jackson, use local classes that only set marker fields or perform canary DNS lookup; do not load gadget chains, JNDI endpoints, or production classpaths.

## Replayable validation boundaries

### Snipe-IT API mass assignment and selectlist enumeration

- Preconditions: owned Snipe-IT lab, disposable user accounts, known role assignments, and non-sensitive test users/assets.
- Baseline the user's current permissions and expected API denials.
- Attempt self-update, user-create, CSV-import, bulk-update, accessory-create, file-delete, and S3-signature retrieval requests that include fields or object IDs beyond the user's assigned role/company. Use harmless read/list permissions, synthetic companies, disposable assets, and marker files as the canary.
- Query selectlist endpoints with a logged-in low-privileged session and verify whether user IDs or identity metadata appear outside the role's expected scope.
- Positive evidence: before/after permission and tenant matrices, endpoint response codes, synthetic cross-company object placement, and redacted user-ID enumeration counts from lab accounts.

### Mattermost integration and team-ID authorization drift

- Preconditions: Mattermost lab in the affected version range, disposable teams/channels, a low-privileged authenticated user, and synthetic integration/playbook objects.
- For integration action URLs, compare path normalization between the configured integration URL and the API route ultimately invoked. Use harmless read/status or synthetic object routes only.
- For playbook runs, submit paired create-run requests where the permission-bearing team and target team differ.
- Positive evidence: route-decision table showing the privileged token or target-team mismatch with only disposable resources affected.

### Camel K build resource namespace steering

- Preconditions: disposable cluster or namespace, Camel K affected version, low-privileged namespace user, and no production operator namespace.
- Create only inert `Build` resources and inspect generated pod metadata, namespace placement, service account, and image references.
- Positive evidence: Kubernetes events or object YAML showing cross-namespace placement attempted or accepted.
- Stop before running arbitrary build steps, mounting secrets, or using real operator service accounts as proof.

### Algernon Host-to-filesystem join

- Preconditions: owned Algernon lab started with `--domain` or `--letsencrypt`, a document root, and one synthetic canary file in the parent directory.
- Send paired baseline and altered-Host requests and compare which filesystem root is selected.
- Positive evidence: retrieval or directory listing of only the synthetic parent canary, plus patched or hardened rejection if available.
- Do not read certificates, keys, logs, configs, user content, or sibling sites.

### Jackson type and DNS canaries

- Preconditions: local harness using the application's `ObjectMapper` configuration, disposable canary classes, and an owned DNS interaction domain.
- Test generic type IDs where the allowed raw container wraps a denied inert canary class.
- Test array-wrapped type IDs where the array shape is allowed but the component class should not be.
- Test `InetSocketAddress` JSON binding with an owned canary DNS name and verify whether resolution occurs during `readValue`.
- Positive evidence: exception/no-exception matrix, marker-field population for inert classes, and DNS query timestamps. Avoid real gadget classes or external callbacks beyond owned DNS canaries.

## Reporting notes

- Lead with the precise trust boundary: **self permission fields**, **selectlist enumeration**, **integration URL to admin-token API**, **team ID mismatch**, **CRD namespace steering**, **Host header to filesystem path**, or **Jackson type/DNS binding**.
- Include version, role, endpoint or object kind, sanitized request shape, expected authorization decision, actual decision, and a patched negative control when possible.
- Keep all proof artifacts disposable: synthetic accounts, teams, namespaces, marker files, inert Java classes, and owned canary domains.
- Do not include real user lists, production admin API results, Kubernetes secrets, filesystem secrets, or executable gadget payloads in wiki/report evidence.
