# Capsule tenant-resource escalation and Symfony sanitizer URL-attribute batch (GHSA, 2026-05-28)

**Signal:** GitHub Advisory Database published a May 28 batch with reusable offensive-operator value for Kubernetes multi-tenant control planes and rich-text sanitizers. The durable lesson is boundary mismatch: namespacing a cluster-scoped object does not constrain it, namespace subresources can bypass namespace webhooks, and sanitizer URL checks must cover every URL-valued attribute the allowlist admits.

Promoted items:

- `GHSA-qjjm-7j9w-pw72` / `CVE-2026-22872`: Capsule `< 0.13.0` `TenantResource.spec.rawItems` can ask the cluster-admin controller to create cluster-scoped resources such as `ClusterRole` or `ValidatingWebhookConfiguration`; `obj.SetNamespace()` is ignored by Kubernetes for cluster-scoped kinds.
- `GHSA-2ww6-hf35-mfjm` / `CVE-2026-30963`: Capsule `< 0.13.0` namespace ownership validation misses `namespaces/status` and `namespaces/finalize`, allowing namespace hijack when a tenant admin has patch/update rights on those subresources.
- `GHSA-hhg7-c65m-h7ff` / `CVE-2026-45753`: Symfony `html-sanitizer` / `symfony/symfony` URL scheme validation omitted `action`, `formaction`, `poster`, and `cite`; permissive configs can preserve `javascript:` URIs in those attributes.

Use this only in authorized tests. Keep proofs minimal: create harmless marker objects in lab or scoped test tenants, use tester-owned callback URLs, and stop before cross-tenant data access, webhook disruption, credential access, or production cluster changes.

## Operator checklist

### 1. Capsule `TenantResource.rawItems` cluster-scope privilege boundary

Where to look:

- Kubernetes clusters using Capsule / Project Capsule versions before `0.13.0`.
- Multi-tenant clusters where tenant owners can create or modify `TenantResource` objects.
- Capsule deployments whose controller service account is bound to broad or `cluster-admin` privileges.

Safe validation path:

1. Confirm Capsule version and controller RBAC with read-only evidence where possible: Helm values, manifests, SBOMs, `kubectl get deploy -n capsule-system`, and `kubectl get clusterrolebinding capsule-manager-rolebinding -o yaml`.
2. Confirm the test tenant identity can create `tenantresources` but cannot directly create a chosen cluster-scoped marker kind, for example `kubectl auth can-i create tenantresources --as <tenant-user> -n <tenant-ns>` and `kubectl auth can-i create clusterroles --as <tenant-user>`.
3. In a lab or explicitly scoped test cluster, submit a `TenantResource` with a harmless cluster-scoped marker such as a `ClusterRole` named with a tester prefix and no dangerous verbs.
4. Verify whether the Capsule controller creates the cluster-scoped object despite the tenant namespace being set in the raw item processing path.
5. Delete the marker object immediately after capture. Do not create admission webhooks, wildcard RBAC, secret-reading roles, or objects that affect unrelated tenants unless the program explicitly provides a safe sandbox for that proof.

Evidence to capture:

- Capsule version and controller RBAC binding.
- Tenant user permissions showing the direct action is denied.
- The minimal `TenantResource` manifest and the resulting cluster-scoped marker object.
- Controller logs or events linking the object creation to the Capsule controller.

Reporting heuristic: strong reports prove **tenant-scoped input plus controller cluster-admin authority plus cluster-scoped output that the tenant could not create directly**. Frame impact as cross-tenant privilege escalation / cluster control-plane object creation, not as a generic Kubernetes misconfiguration.

### 2. Capsule namespace subresource hijack boundary

Where to look:

- Capsule versions before `0.13.0` that rely on validating webhooks to prevent namespace ownership changes.
- Tenants or delegated roles with patch/update access to `namespaces/status` or `namespaces/finalize`.
- Clusters exposing self-service namespace or tenant lifecycle automation where subresource rights may have been granted indirectly.

Safe validation path:

1. Confirm the webhook rules include `namespaces` but not the relevant namespace subresources.
2. Confirm the attacker-like tenant identity has patch rights on `namespaces/status` or `namespaces/finalize`; without those rights, document it as not exploitable in that environment.
3. In a lab or program-provided sandbox, create two test tenants and a disposable namespace owned by the first tenant.
4. Patch only the disposable namespace's metadata owner reference through the status or finalize subresource to point to the second tenant.
5. Verify Capsule accepts the ownership change while the normal namespace update path would have been rejected.

Evidence to capture:

- Webhook rule set and missing subresource coverage.
- `kubectl auth can-i patch namespaces/status` or equivalent permission proof.
- Before/after owner references for a disposable namespace.
- Capsule tenant visibility or access change after the patch.

Reporting heuristic: this is high-signal only when the target grants namespace subresource mutation to a tenant-like principal. Without that permission, keep it as a configuration exposure note rather than a confirmed exploit path.

### 3. Symfony `html-sanitizer` missing URL-attribute scheme checks

Where to look:

- Composer projects using `symfony/html-sanitizer` or `symfony/symfony` in `>= 6.1.0, < 6.4.40`, `>= 7.0.0, < 7.4.12`, or `>= 8.0.0, < 8.0.12`.
- Rich-text fields, CMS blocks, ticket/comment systems, profile bios, documentation portals, email templates, and WYSIWYG preview surfaces that allow custom HTML.
- Configurations using `allowStaticElements()`, wildcard attributes, or explicit `allowAttribute()` / `allowElement()` calls for `form[action]`, `button[formaction]`, `input[formaction]`, `video[poster]`, or quote/change tags with `cite`.

Safe validation path:

1. Confirm the sanitizer version and that the dangerous attribute is intentionally admitted by configuration. `allowSafeElements()` alone is not enough for the `form` / `formaction` path.
2. Submit inert HTML in a tester-controlled field, using visible text and a non-exfiltrating marker. Examples: a form with `action="javascript:console.log('skillz-marker')"`, a button with `formaction`, or a quote element with `cite="javascript:..."`.
3. Inspect the sanitized output before clicking anything. The core proof is that a `javascript:` or otherwise off-policy URL survives in an admitted URL attribute.
4. For `action` / `formaction`, if interaction proof is needed, use a disposable test account and a harmless marker only; do not phish or trigger actions from real users.
5. Check propagation into stored pages, previews, exports, notifications, and webviews, because sanitizer results often travel beyond the original input surface.

Evidence to capture:

- Package version, sanitizer configuration, and input location.
- Raw HTML and sanitized/rendered HTML showing the preserved URL-valued attribute.
- Whether exploitation requires user interaction, same-origin script execution, or only visual/navigation deception.
- Output context: stored, reflected, preview-only, email, export, or webview.

Reporting heuristic: strong reports show **untrusted HTML plus a permissive sanitizer allowlist plus an unvalidated URL-valued attribute that reaches a user-viewed context**. Separate script execution from click-required form/navigation impact.

## Non-signal this hour

Reviewed but not promoted as standalone Skillz guidance:

- `GHSA-5wrp-cwcj-q835` / `CVE-2026-41178` OpenTelemetry Go baggage header parsing CPU/log amplification. It is remotely reachable in instrumented services but availability-only, bounded by upstream header limits, and not a durable offensive workflow for this wiki.
- CISA KEV advanced to catalog `2026.05.28`, but the top entries remained the May 27 Nx Console, TanStack, and Daemon Tools Lite items plus previously reviewed LiteSpeed / Drupal / Langflow entries; no new Skillz operator workflow was added.
- PortSwigger Research stayed on Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis article.
- ProjectDiscovery `/blog/rss` stayed on already-covered Neo / Nuclei / DAST material; `/blog/rss.xml` still returned 404.
- GitHub Security Blog stayed GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [Capsule TenantResource rawItems cluster-scoped resource advisory (`GHSA-qjjm-7j9w-pw72`)](https://github.com/advisories/GHSA-qjjm-7j9w-pw72)
- [Capsule namespace subresource hijack advisory (`GHSA-2ww6-hf35-mfjm`)](https://github.com/advisories/GHSA-2ww6-hf35-mfjm)
- [Symfony HtmlSanitizer URL-attribute advisory (`GHSA-hhg7-c65m-h7ff`)](https://github.com/advisories/GHSA-hhg7-c65m-h7ff)
