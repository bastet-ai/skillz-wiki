# Pangolin share-link cross-org auth bypass and OpenSearch SQL cursor deserialization, operator…

**Date reviewed:** 2026-08-31 (unreviewed GitHub advisory wave, published 2026-08-31)
**Primary advisories:** [GHSA-gqgf-x763-r89w / CVE-2026-72001](https://github.com/advisories/GHSA-gqgf-x763-r89w) (high, 8.6, CWE-639), Pangolin; [GHSA-rj55-cp95-h7f6 / CVE-2026-83497](https://github.com/advisories/GHSA-rj55-cp95-h7f6) (high, CWE-502), OpenSearch SQL plugin.
**Boundary class:** (1) a scoped auth token whose **resource binding is caller-selectable**, one valid share-link token authenticates against arbitrary resources across organizations; (2) an **opaque pagination cursor deserialized with no type confinement** on a basic-permission SQL endpoint, a classic deserialization-to-RCE surface.

These are durable because both are reusable operator patterns, not product-specific quirks: **trust the token, not the resource it was issued for**, and **an opaque token the client round-trips is a deserialization input**.

## 1. Pangolin: share-link endpoint omits the resource identifier from token verification (CWE-639)

Pangolin's share-link authentication endpoint accepts a caller-controlled URL parameter and, on the affected builds, the token-verification call **omits the expected resource identifier**, so the token is checked for *validity* but not bound to the specific resource being requested. An attacker holding **a single valid share link for any one resource** can therefore authenticate against **arbitrary resources in other organizations**, and the bypass defeats every configured secondary control at once: SSO, resource passwords, PIN codes, email allowlists, and header authentication. The result is cross-tenant data access without a second credential.

- **Affected:** Pangolin `< 1.22.0`.
- **Patched:** `1.22.0`.
- **Severity:** high (CVSS 8.6).

The reusable pattern: a token/credential that is **validated but not re-bound to the object being accessed** at request time. The token proves "this link is real"; it does not prove "this link is for *this* resource, *this* tenant." Any scoped link (share link, signed URL, one-time token, capability URL) is a candidate when the verification call can be steered to skip the object/tenant binding.

### Operator triage

1. Inventory share-link / capability-URL / signed-URL auth on the target. For each, ask: **does the verification step re-check the resource ID and tenant/org against the token, or does it only check token signature/expiry?** A verification call that can be steered (parameter, path segment, header) to omit the resource identifier is the primitive.
2. Confirm which secondary controls the product relies on (SSO, per-resource password, PIN, allowlist, header auth). A binding bypass defeats all of them at once, that is what makes a scoped-link bug high/critical rather than a narrow IDOR.
3. Prioritize deployments where a single user can mint or hold any share link (most SaaS/file-share/document products do), and where resources are partitioned by organization/tenant.

### Replayable validation (lab / owned tenants only)

Preconditions: an authorized lab Pangolin `< 1.22.0` (or a minimal harness reproducing the share-link verification sink), two lab tenants/orgs, and two lab resources with known canary content. No production data, no real tenants, no exfiltration to external hosts.

1. **Mint one valid share link** for a canary resource in Tenant A. Confirm the link works for that resource.
2. **Drive the share-link auth endpoint at a Tenant B resource.** The proof is that the endpoint accepts the Tenant A link and returns the Tenant B canary, the token was validated but the resource/tenant binding was not enforced. Record the exact parameter/segment you steered and the verification call that skipped it.
3. **Confirm secondary-control defeat.** If Tenant B uses SSO/PIN/allowlist in the lab, show that the same link bypasses those checks, that is the advisory's cross-tenant impact.
4. **Negative control.** Repeat against `1.22.0` (or a patched verification call): the Tenant A link must be rejected for the Tenant B resource.
5. Capture: affected version, the steered parameter, the two-tenant canary readback, and the patched negative control. Stop at the canary, do not read real cross-tenant data, credentials, or secrets.

## 2. OpenSearch SQL plugin: cursor pagination deserialization to RCE (CWE-502)

The OpenSearch SQL plugin's `plugins/sql` endpoint paginates results with an **opaque cursor** the client round-trips. On affected builds the cursor is **deserialized with unrestricted class loading** instead of being treated as an opaque, type-constrained token. A remote authenticated user with only **basic read/search permissions** can send a **crafted cursor parameter** and trigger arbitrary code execution on the server. The AWS security bulletin (2026-092) corroborates the AWS OpenSearch Service exposure.

- **Affected:** OpenSearch SQL plugin on OpenSearch `2.x` < 2.19.6 and `3.x` < 3.7.0.
- **Patched:** `2.19.6` / `3.7.0` (and corresponding AWS service versions).
- **Severity:** high.

The reusable pattern: **an "opaque" pagination/state token that the server deserializes into objects is a deserialization sink.** "Opaque" is only as safe as the class allowlist on the deserializer. If the client controls the bytes and the server unmarshals them with a default/lenient deserializer, you have a read- or write-authorized user a single crafted token away from RCE. This is the same primitive as the many "cursor"/"state"/"encoded pagination token" RCEs in web frameworks, hunt for it wherever a client round-trips a server-issued token.

### Operator triage

1. For any API that returns a pagination cursor / "next" token / encoded state the client must send back, identify the **deserializer** that decodes it and whether it has a **class allowlist** or treats the token as opaque base64/JSON with no object instantiation.
2. Note the **permission floor**: here it is basic read/search, not admin. A low-privilege deserialization RCE is the highest-value variant, it means any reader can become code execution.
3. Prioritize OpenSearch / AWS OpenSearch Service deployments where the SQL plugin is enabled and low-privilege search users exist.

### Replayable validation (lab / owned instance only)

Preconditions: an authorized lab OpenSearch `2.x`/`3.x` in the affected range with the SQL plugin, a low-privilege lab user with read/search access, and a lab-only deserialization probe. No production clusters, no real data, no cloud metadata, no lateral movement.

1. **Baseline:** run a normal paginated SQL query; capture the cursor the response returns and confirm it round-trips on the next request.
2. **Type the token:** decode the cursor to see its format (JSON/base64/serialized object). The target is the deserialization entry point, the exact class is product/version-specific and is not reproduced here.
3. **Prove the deserialization surface, not production RCE:** in the lab, show that a crafted cursor reaches the deserializer and instantiates a marker/controlled class (an inert canary class that records it was constructed), establishing the primitive. In an authorized assessment, a lab-only marker class or a documented, denied deserializer sink is the complete proof, you do not need to execute a payload against retained data.
4. **Negative control:** the same crafted cursor against a patched build (`2.19.6`/`3.7.0`) must be rejected or safely decoded.
5. Capture: OpenSearch + plugin version, the low-privilege user context, the cursor format, the marker-class construction evidence, and the patched negative control. Stop at the marker, no real RCE, no secret access, no lateral movement.

## Reporting heuristics

- **Pangolin:** frame as **scoped-token resource/tenant binding bypass** (CWE-639). Strong reports name the exact parameter that steers the verification call, show one valid link authenticating across two tenants, and demonstrate that the secondary controls (SSO/PIN/allowlist/header) are all defeated at once. Keep proof to lab two-tenant canaries.
- **OpenSearch SQL:** frame as **client-controlled opaque cursor deserialization** (CWE-502) on a **low-privilege** endpoint. Emphasize the permission floor (basic read/search → RCE) and the deserializer/class-allowlist boundary. Prove with a marker class or a denied deserializer sink; do not run production payloads or touch real data.
- Both records came from the 2026-08-31 unreviewed advisory wave, which also included a large batch of sparse product-specific records (WordPress plugin/theme unauthenticated SQLi/XSS/IDOR/broken-auth themes, a FastGPT `getHistories` NoSQL-injection record, a multi-record TOTOLINK T6 router access-control wave, and re-surfaced older advisories). Those were reviewed and marked processed **without publication** because they are product-specific with no reusable operator boundary.

## Safety and authorization notes

These pages are for lawful research, lab work, and authorized assessments. Do not apply them to systems you do not own or lack explicit permission to test. No production instances, no real tenant/user data, no cloud metadata, no lateral movement, no exfiltration to external hosts. Identity/tenant markers and inert canary classes only, do not capture real credentials, secrets, cross-tenant data, or run destructive commands.

## Sources

- [GitHub Advisory Database: Pangolin GHSA-gqgf-x763-r89w / CVE-2026-72001](https://github.com/advisories/GHSA-gqgf-x763-r89w)
- Pangolin 1.22.0 release: <https://github.com/fosrl/pangolin/releases/tag/1.22.0>
- VulnCheck advisory: <https://www.vulncheck.com/advisories/pangolin-authentication-bypass-via-share-link-endpoint>
- [GitHub Advisory Database: OpenSearch SQL GHSA-rj55-cp95-h7f6 / CVE-2026-83497](https://github.com/advisories/GHSA-rj55-cp95-h7f6)
- AWS security bulletin 2026-092: <https://aws.amazon.com/security/security-bulletins/2026-092-aws>
- OpenSearch release artifacts: <https://opensearch.org/artifacts/by-version/>
