# Nezha, Papra, Pipecat, SimpleSAMLphp, and Hulumi boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-8qhj-4f8c-j8qg](https://github.com/advisories/GHSA-8qhj-4f8c-j8qg) / CVE-2026-49396 and [GHSA-vrmh-5mmx-hjwx](https://github.com/advisories/GHSA-vrmh-5mmx-hjwx) / CVE-2026-49397 for Nezha, [GHSA-5g86-85rp-f9hx](https://github.com/advisories/GHSA-5g86-85rp-f9hx) / CVE-2026-48051 for Papra, [GHSA-mqq6-462x-jxmm](https://github.com/advisories/GHSA-mqq6-462x-jxmm) / CVE-2026-48031 for Go Restful API Boilerplate, [GHSA-3363-2ph6-35wh](https://github.com/advisories/GHSA-3363-2ph6-35wh) / CVE-2026-44716 for Pipecat Runner, [GHSA-jrrg-99xh-5j2q](https://github.com/advisories/GHSA-jrrg-99xh-5j2q) / CVE-2026-46491 for SimpleSAMLphp `casserver`, and Hulumi policy-pack advisories [GHSA-rhgj-6g2c-frmm](https://github.com/advisories/GHSA-rhgj-6g2c-frmm), [GHSA-9vc9-4jv3-rf86](https://github.com/advisories/GHSA-9vc9-4jv3-rf86), and [GHSA-g759-4pxw-6692](https://github.com/advisories/GHSA-g759-4pxw-6692).

This batch is durable because it turns sparse advisories into reusable operator checks for state-changing GET endpoints, webhook redirect SSRF, hardcoded JWT secrets in copied boilerplates, encoded-separator file reads, CAS ticket-store path traversal, and IaC policy-gate bypasses that can hide dangerous cloud resources in pull requests.

## What changed

- **Nezha stored cron CSRF** — authenticated manual cron execution is exposed as `GET /api/v1/cron/:id/manual`. Dashboard JWTs can be sent in the `nz-jwt` cookie with `SameSite=Lax`, so a top-level cross-site navigation can trigger a victim user's already-saved cron command on eligible agents. The issue does not create or edit cron commands by itself.
- **Nezha hidden-service enumeration** — services marked `EnableShowInService: false` are filtered from the main service listing, but adjacent readers such as `GET /api/v1/server/:id/service` and `GET /api/v1/service/:id/history` can still disclose hidden service names and timing data through optional-auth paths.
- **Papra webhook redirect SSRF** — webhook URL validation checks the registered URL, but the delivery HTTP client follows redirects. An authenticated organization member can register an assessment-controlled webhook that returns a 3xx to loopback, link-local, or RFC1918 targets unless redirect destinations are revalidated.
- **Go Restful API Boilerplate hardcoded JWT secret** — applications copied from `github.com/dhax/go-base` can inherit a default `AUTH_JWT_SECRET` / `auth_jwt_secret` value of `random`, allowing HS256 token forgery when the deployment did not replace the secret.
- **Pipecat Runner encoded-slash traversal** — the development runner's `/files/{filename:path}` endpoint joins the caller-supplied filename under `--folder` without a containment check. Literal `../` may be normalized by routing, but `%2F`-encoded separators can survive until after route matching and escape the folder.
- **SimpleSAMLphp CAS FileSystemTicketStore traversal** — public CAS validation/proxy parameters such as `ticket` or `pgt` can flow into file-based ticket-store path construction. Traversal can read and unserialize files outside the ticket directory; CAS 1.0 validation can also conditionally delete a readable/deletable serialized target.
- **Hulumi policy-pack bypasses** — cloud policy gates trusted Pulumi URN substrings, sibling resource types, or a single federated principal shape without enough structural binding. A malicious or compromised infrastructure change can name a raw resource like a trusted component, add decoy hardening siblings for a different bucket, or hide GitHub OIDC trust inside a multi-provider principal array.

## Operator triage

1. **Find Nezha panels and roles:** identify scoped Nezha dashboards, version evidence, `nz-jwt` cookie attributes, existing cron tasks, public server IDs, and whether hidden services are relied on for tenant or customer privacy.
2. **Prioritize state-changing GETs:** crawl authenticated admin and monitoring panels for `GET` routes with names like `manual`, `trigger`, `run`, `sync`, `deploy`, `restart`, or `test`. Check whether cookies are sent on top-level cross-site navigation.
3. **Trace webhook redirect behavior:** for Papra-like webhook systems, test both registration-time validation and delivery-time redirect handling. A safe SSRF check validates that the first hop is allowed and the redirected hop is blocked or surfaced.
4. **Fingerprint copied boilerplates:** search scoped Go services for `github.com/dhax/go-base`, `go-chi/jwtauth`, `AUTH_JWT_SECRET`, and fallback strings such as `random`. Do not assume every application copied from a boilerplate retained the weak default.
5. **Separate dev runners from production apps:** Pipecat Runner exposure is most valuable when a development runner is bound beyond localhost or reachable from shared notebooks, demos, or agent workspaces.
6. **Check CAS ticket-store mode:** SimpleSAMLphp impact depends on the `casserver` module, `FileSystemTicketStore`, reachable validation/proxy endpoints, and PHP filesystem permissions.
7. **Review IaC guardrails as bypassable code:** when a program relies on Pulumi/Hulumi policy packs, review the actual resource graph and generated plan, not just the green policy result. Look for trusted substrings in logical names, sibling resources that point to a different target, and IAM roles with GitHub OIDC mixed into provider arrays.

## Replayable validation boundaries

### Nezha cron and service visibility

- Use a lab dashboard or an explicitly approved low-risk account with a benign existing cron such as `printf skillz-nezha-csrf-canary`.
- Build a one-line HTML link or form that navigates to `/api/v1/cron/<id>/manual` from a different origin. Vulnerable evidence is a top-level navigation that triggers the stored cron using the victim's cookie.
- Do not create destructive cron commands, run reverse shells, or fan commands across production agents unless the customer explicitly approved that escalation.
- For hidden services, query the main service list and the adjacent per-server/history endpoints with unauthenticated or guest access. Strong evidence shows a service absent from the public list but present by name or timing data through the adjacent route.

### Papra redirect SSRF

- Register a webhook to an assessment-controlled HTTPS endpoint that logs only request metadata and returns a single redirect to a benign canary target.
- Use safe targets: a collaborator endpoint, a lab-only loopback listener, or a non-sensitive internal canary explicitly provided by the owner. Do not probe cloud metadata, admin panels, or secret-bearing endpoints.
- Evidence should include the registered URL, redirect `Location`, delivery request metadata, and whether the server followed the redirect.

### Hardcoded JWT secret proof

- Confirm the application derives from the affected boilerplate and that the deployed signing key is still the default before attempting token forgery.
- In a lab or with an approved test account, mint an HS256 token using the default key and a low-privilege synthetic subject. A vulnerable deployment accepts the forged token for an authenticated route.
- Redact real claims and tokens. Avoid forging admin claims unless an escalation proof is explicitly authorized and needed.

### Pipecat Runner file-read proof

- Validate only on disposable runners or approved dev systems. Create a synthetic marker file outside the configured `--folder` but readable by the runner process.
- Request the marker through an encoded-separator path such as a `%2F`-encoded traversal. Stop after proving containment escape with the marker.
- Do not read SSH keys, notebooks, credentials, model weights, prompt logs, or user files.

### SimpleSAMLphp CAS ticket-store proof

- Confirm `casserver` and `FileSystemTicketStore` before testing. If the deployment uses a database or memory store, this path is likely not applicable.
- Use a synthetic serialized marker in a lab path readable by PHP. Test whether a traversing `ticket` or `pgt` parameter causes the server to access that marker.
- Avoid using production files as targets. Do not attempt deletion proofs outside a disposable lab because CAS 1.0 validation can conditionally delete files.

### Hulumi policy-gate bypass proof

- Keep proofs in a throwaway Pulumi stack or a pull request against an intentionally disposable account.
- Demonstrate one bypass at a time: a raw resource whose logical name contains a trusted component substring, hardening sibling resources bound to a different S3 bucket, or an IAM role with GitHub OIDC plus a second federated provider and wildcard `sub` conditions.
- Evidence should show the policy pack reporting compliance while the rendered plan contains the unsafe resource shape. Do not deploy unsafe cloud resources into production.

## Reporting heuristics

- Lead with the trust boundary that failed: **browser navigation to stored command**, **visibility flag bypass through adjacent readers**, **redirect target not revalidated**, **default signing key inherited from boilerplate**, **encoded path separators escaping a runner folder**, **ticket IDs crossing into filesystem paths**, or **policy checks trusting names instead of bound resources**.
- Include exact preconditions and role level. Several issues require authentication or an existing stored object; overclaiming them as pre-auth RCE weakens the report.
- Prefer synthetic canaries over sensitive data. Strong reports do not need real agent output, internal files, SAML tickets, JWT secrets, or cloud credentials.
- When batching multiple findings on one target, chain only what was actually proven: for example, webhook SSRF plus a reachable internal runner is a separate chain from either issue alone.
