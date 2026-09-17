# ChromaDB tenant-authorization bypass and model-loading RCE wave

Source: GitHub Security Advisories REST `updated` feed, 2026-08-24 (advisories first published 2026-06-12, re-surfaced this hour): [GHSA-36p7-vc44-83pf](https://github.com/advisories/GHSA-36p7-vc44-83pf) / [CVE-2026-45833](https://nvd.nist.gov/vuln/detail/CVE-2026-45833), [GHSA-xph7-9rjv-w5fr](https://github.com/advisories/GHSA-xph7-9rjv-w5fr) / [CVE-2026-45831](https://nvd.nist.gov/vuln/detail/CVE-2026-45831), [GHSA-2wm9-hf6c-p5cr](https://github.com/advisories/GHSA-2wm9-hf6c-p5cr) / [CVE-2026-45830](https://nvd.nist.gov/vuln/detail/CVE-2026-45830), and [GHSA-x97m-f58v-9cwg](https://github.com/advisories/GHSA-x97m-f58v-9cwg) / [CVE-2026-45832](https://nvd.nist.gov/vuln/detail/CVE-2026-45832). Vendor disclosure: [HiddenLayer SAI ChromaDB advisory](https://www.hiddenlayer.com/sai-security-advisory/2026-06-chromadb).

This wave is durable because it captures a reusable AI/ML vector-store tenant-boundary pattern: the authorization layer accepts a permission name but never binds it to the tenant / database / collection the request is scoped to, and the collection resolver keys on the UUID alone. When that is combined with the collection-update model-loading path and `trust_remote_code`, an authenticated low-privilege tenant user reaches arbitrary code execution on the server. This is the same family as the [2026-05-29 ChromaDB pre-auth model-loading batch](2026-05-29-chromadb-ngrok-tar-capi-boundary-batch-ghsa.md#chromadb-python-server-model-loading-check) but scoped to the *post-auth* tenant/permission model rather than the pre-auth ordering.

## What changed

All four advisories affect the `chromadb` Python package in roughly `>= 0.4.17, <= 1.5.9` (RCE and cross-tenant CRUD from `0.4.17`; the RBAC scope-check gap from `0.5.0`). No fixed version was published in the advisories at scan time; treat every in-range Python Chroma server as in-scope for these boundaries.

- **Cross-tenant arbitrary collection CRUD (CVE-2026-45830 / GHSA-2wm9-hf6c-p5cr, high).** A lack of authorization validation lets any authenticated user read, write, update, or delete data in *any* tenant's collection regardless of which tenant they belong to.
- **V1 API tenant isolation bypass via null context (CVE-2026-45832 / GHSA-x97m-f58v-9cwg, high).** All V1 collection-level endpoints pass `None` for tenant and database to the authorization layer, so tenant-scoped access control is impossible through V1 regardless of which authorization provider is configured. V1 cannot be disabled. The collection resolver (`_get_collection`) keys purely on the UUID, so with CVE-2026-45830 an authenticated user gets unrestricted read/write to any collection by UUID.
- **RBAC provider never checks the object the permission applies to (CVE-2026-45831 / GHSA-xph7-9rjv-w5fr, high).** `SimpleRBACAuthorizationProvider` evaluates *whether a user holds a permission* but never checks *which tenant/database/collection* that permission applies to, so a user's granted permission is honored cross-tenant.
- **Post-auth RCE via `update_collection` + `trust_remote_code` (CVE-2026-45833 / GHSA-36p7-vc44-83pf, critical).** An authenticated user with `UPDATE_COLLECTION` permission can send a malicious model repository name with `trust_remote_code: true` to `POST /api/v2/tenants/{tenant}/databases/{db}/collections/{collection_id}` to run arbitrary code on the server.

## Operator triage

1. **Identify exposed ChromaDB Python servers:** prioritize internet-facing Chroma `/api/v1/` and `/api/v2/` routes, API docs pages, Docker images, and process names indicating the Python FastAPI server. Capture version evidence at or after `0.4.17`.
2. **Determine auth mode:** these are post-auth. Confirm whether the deployment is tokenless/local (any request is "authenticated"), uses the built-in RBAC provider, or a custom `AuthorizationProvider`. The null-tenant V1 bypass (45832) applies regardless of provider.
3. **Map the tenant/permission model:** look for multi-tenant or multi-database deployments, RAG admin panels, and tenant self-service APIs where different logical tenants share one Chroma instance.
4. **Find the model-loading surface:** any path that lets a user set an embedding-function / model repository id and a `trust_remote_code` flag through collection create/update, tenant self-service, or an admin panel is the RCE trigger.
5. **Prioritize by blast radius:** a single-tenant, trusted-admin-only instance is defense-in-depth. A shared multi-tenant vector store where tenants are the trust boundary is a red-team-grade escalation.

## Replayable validation boundaries

### Cross-tenant collection authorization check

- **Two-tenant lab setup:** stand up one Chroma Python server, create two tenants (A and B) each with a collection holding a synthetic canary document. Use a fresh, throwaway data directory.
- **Bind the session to tenant A:** obtain an A-tenant session/token. Then call a V1 or V2 collection endpoint with tenant B's collection UUID.
- **Prove the primitive, one operation at a time:** test read (list/peek/get), write (add upsert/delete) against the B-tenant canary separately. Stop at the canary being returned or mutated. Do not read, exfiltrate, or delete real tenant data, embeddings, or stored secrets.
- **Record the authorization decision:** capture the request, the tenant/database context passed, the 200/201 vs 403 response, and the canary effect. This proves the missing tenant binding.

### RBAC scope-check gap check

- **Grant a narrow permission:** give a low-priv user `UPDATE_COLLECTION` on one specific collection in tenant A.
- **Exercise the same permission on tenant B's collection:** if the provider only checks the permission name, the cross-tenant mutation succeeds. Prove it with a canary document only.

### Model-loading RCE check (post-auth)

- **Version and route proof first:** capture the ChromaDB version, the `UPDATE_COLLECTION`-authorized session, and the exact `update_collection` route before sending any payload.
- **Use a controlled benign model repo in a lab:** host a minimal Hugging Face-compatible model repository that performs a harmless canary action — request a tester-owned callback URL or write a marker to a disposable path inside the container.
- **Prove post-auth execution safely:** with the authorized session, send an `update_collection` body that sets the controlled model name and `trust_remote_code: true`. Verify the benign canary fired. Do not read environment variables, tokens, collection data, or mounted secrets on production systems.
- **Distinguish from the pre-auth batch:** this path requires a valid `UPDATE_COLLECTION` session. Note that explicitly so the report is not conflated with the 2026-05-29 pre-auth ordering finding.

## Reporting heuristics

- Frame the core finding as a **tenant-boundary authorization gap**: the permission is granted but not scoped to the tenant/database/collection the request names, and the collection resolver keys on the UUID alone.
- Include the exact endpoint, the tenant/database context sent, the authorization provider in use, and the canary evidence for each primitive (read / write / RCE).
- For the RCE, highlight the **post-auth model-loading side effect** and the `trust_remote_code` precondition. Include the endpoint, the model-repo field, and the callback proof.
- State the version range and that no fixed version was published at scan time; recommend pinning/patching and isolating tenants by instance where a fix is unavailable.
- Separate the four CVEs in the report even though they chain: 45830/45832 (cross-tenant CRUD + V1 bypass), 45831 (RBAC scope), 45833 (RCE).

## Safety

- **Authorized, in-scope targets only.** Multi-tenant vector stores are often production RAG backends; probing with real collection IDs can be noisy and may touch live embeddings. Coordinate with the asset owner.
- **No production data access.** Use synthetic canary documents in a lab mirror. Never read, exfiltrate, or delete real tenant data, embeddings, or stored credentials to "prove" the boundary.
- **No live `trust_remote_code` execution on shared hosts.** Prove model-loading with a benign canary repo on an isolated instance.
- **No RCE assumption from the CRUD findings.** 45830/45831/45832 are authorization gaps; only 45833 (model-loading) reaches code execution, and only with the `trust_remote_code` precondition.

## Reviewed but not promoted here

- The vendor advisory also lists **CVE-2026-45829** (a pre-auth `config()` model-loading path already covered by the [2026-05-29 batch](2026-05-29-chromadb-ngrok-tar-capi-boundary-batch-ghsa.md)); not re-promoted.
- No KEV entry and no active-exploitation status attached to this wave at scan time; treat as a patch/patched-by-configuration priority, not active-exploitation.

## September 16 follow-up: Chroma tenant/database segments unvalidated in collection resolution

[GHSA-j8fq-8cc8-m22c](https://github.com/advisories/GHSA-j8fq-8cc8-m22c) / CVE-2026-92782: Chroma through 1.5.9 does not validate the **tenant and database segments** when resolving collections — an authenticated caller issuing requests under its own tenant path but naming a foreign collection identifier can read, modify, and update records in other tenants' collections. Same UUID-keyed-resolution root cause as the Aug 24 wave on this page; treat it as confirmation that the tenant segment remained decorative in the resolver through 1.5.x.

Operator replay unchanged: two-tenant lab, synthetic canary docs, one operation at a time (peek/add/update under tenant A against tenant B's collection UUID), decision table per V1/V2 route. Add the `1.5.9` boundary to the version-evidence matrix; any engagement checklist item that said "patched past 0.6.x" must be re-run on current releases.
