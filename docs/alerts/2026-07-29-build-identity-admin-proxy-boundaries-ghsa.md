---
title: Build-input, identity, admin, and UI-proxy control boundaries
---

# Build-input, identity, admin, and UI-proxy control boundaries

A July 29 GitHub advisory wave exposes one reusable operator pattern across GNU Bison, Apache Airflow, Keycloak, Apache Atlas, Apache Kyuubi, and a WordPress calculator plugin: **a value approved for one narrow purpose later selects a program, output path, identity, organization, administrative operation, network destination, or evaluator input without preserving the original authority boundary**.

Sources:

- [GHSA-735p-4prj-f62v / CVE-2026-56389: GNU Bison grammar-selected `xsltproc`](https://github.com/advisories/GHSA-735p-4prj-f62v)
- [GHSA-3pcj-vqw8-47jm / CVE-2026-56390: GNU Bison grammar-selected output paths](https://github.com/advisories/GHSA-3pcj-vqw8-47jm)
- [CERT Polska GNU Bison research](https://cert.pl/en/posts/2026/07/CVE-2026-56389/)
- [GHSA-q5r3-w69r-hrfw / CVE-2026-59243: Airflow FAB Azure AD token signature bypass](https://github.com/advisories/GHSA-q5r3-w69r-hrfw)
- [GHSA-rfxv-6gx8-3fm6 / CVE-2026-18207: Keycloak group-name client-policy bypass](https://github.com/advisories/GHSA-rfxv-6gx8-3fm6)
- [GHSA-fvjx-r757-3r6r / CVE-2026-18201: Keycloak IdP-to-organization authorization drift](https://github.com/advisories/GHSA-fvjx-r757-3r6r)
- [GHSA-w667-wgvw-q2hc / CVE-2026-50622: Apache Atlas admin endpoint authorization](https://github.com/advisories/GHSA-w667-wgvw-q2hc)
- [GHSA-qvj4-xxw2-22gf / CVE-2026-23904: Apache Kyuubi Engine UI open proxy](https://github.com/advisories/GHSA-qvj4-xxw2-22gf)
- [GHSA-pm79-7c72-f572 / CVE-2026-14900: Cost Calculator Builder PRO formula evaluation](https://github.com/advisories/GHSA-pm79-7c72-f572)

The GitHub entries were unreviewed when this page was written. Confirm the primary source, exact affected build, configuration, route, role, and corrected behavior before reporting. GNU Bison 3.8.2 was reportedly tested, but the upstream fixes did not provide a complete vulnerable range. The Kyuubi issue affects 1.8.0 before 1.12.0; the Airflow provider issue affects `apache-airflow-providers-fab` before 3.7.3; the Atlas record covers 0.8 through 2.5.0.

!!! warning "Authorized validation only"
    Use disposable repositories, local identity providers, synthetic realms/groups/organizations, fake tokens, lab-only Atlas and Kyuubi instances, owned HTTP callbacks, and instrumented no-op sinks. Never execute an untrusted grammar on a workstation or CI runner, overwrite shell or application files, forge a production identity, invoke real administrative operations, proxy to metadata/internal services, or pass executable expressions to a live PHP evaluator.

## Build one authority matrix

| Surface | Untrusted selector | Authority that should win | Bounded proof |
| --- | --- | --- | --- |
| Bison HTML report | `%define tool.xsltproc` | trusted executable configured by the caller | recorder binary increments a temp-file counter |
| Bison generation | `%output`, `%header`, related directives | caller-selected output root and filenames | text marker appears only in a disposable sibling path |
| Airflow FAB OAuth | ID-token header, claims, signature | configured issuer/key set, audience, algorithm, callback transaction | synthetic `/me` identity or rejected-token decision |
| Keycloak client policy | group name/path | immutable group ID and required policy profile | duplicate-name group decision matrix |
| Keycloak organization | IdP ID and organization ID | both IdP-management and target-organization permission | marker-only link relation in a disposable realm |
| Apache Atlas admin API | admin route and object | server-side role/capability check | harmless config/status marker or no-op counter |
| Kyuubi Engine UI proxy | path-supplied host and port | enabled feature plus explicit destination allowlist | two owned listeners return distinct canaries |
| WordPress calculator | order field and formula tokens | fixed grammar with no dynamic evaluator | instrumented evaluator counter remains zero |

Record the authorization decision and the sink separately. A parser accepting a field is not proof of execution, a decoded JWT is not proof of login, a reachable route is not proof of an administrative state change, and a URL-shaped path is not proof of SSRF without an owned callback.

## GNU Bison: treat grammars as executable build input

The two Bison records matter whenever pull requests, package sources, code-generation services, documentation jobs, or CI workflows run Bison over contributor-controlled grammar files. HTML report mode reportedly permits a grammar to replace the XML-to-HTML program through `%define tool.xsltproc`; output directives can reportedly override caller-selected destinations.

Use a disposable container with no credentials, network access, repository signing keys, package-manager tokens, or mounted home directory:

1. Copy a minimal known-good grammar into `TEMP/repo` and place a unique text canary in `TEMP/sibling`.
2. Replace the XSLT tool only with a recorder program that writes one fixed marker under `TEMP/evidence`; it must not run a shell or inspect environment variables.
3. Compare ordinary generation, HTML report mode, a grammar-selected recorder, and a caller-selected recorder negative control.
4. For output directives, test normal relative names, nested names, `../sibling/marker.txt`, absolute temp paths, symlinked parents, and a caller-provided output path. Never select startup files, source files, credentials, or system paths.
5. Capture the argv passed to `execvp()`, canonical output path, before/after hashes, process user, and fixed-commit decision.

A bounded positive is **untrusted grammar directive -> Bison overrides the caller's tool or output selection -> no-op recorder executes or inert generated text lands outside the approved output root**. Report program selection and file placement as separate primitives. Do not claim arbitrary code execution from path control alone.

## Airflow FAB: verify identity proof before consuming claims

The advisory says the Azure AD OAuth path decoded ID tokens with `verify_signature=False` by default; the Authentik path reportedly already defaulted to verification. Build a local callback harness and fake issuer rather than crafting a token for a live deployment.

1. Create a disposable Airflow/FAB instance with users `alice-canary` and `admin-canary`, but test only a non-privileged status route.
2. Capture a normal fake-issuer login and bind issuer, audience, nonce/state, algorithm, key ID, subject, email, and resulting user.
3. Generate lab tokens covering valid signature, corrupted signature, unsigned form, wrong issuer, wrong audience, stale timestamps, unknown key, and changed subject. Keep signing keys local and disposable.
4. Instrument session creation or request only `/me`; prove which synthetic identity would be selected without accessing administrator functions.
5. Repeat on provider 3.7.3 with signature verification explicitly enabled and preserve the decision table.

The finding is **invalid or absent signature -> callback consumes attacker-selected claims -> synthetic session identity is selected**. Redact complete tokens, cookies, codes, keys, and callback parameters. Do not publish a reusable unsigned-token sample.

## Keycloak: separate names, immutable IDs, and resource permissions

### Duplicate group names versus client policy

Create two group branches with the same leaf name but different immutable IDs. Put a disposable client manager in only the non-authorized branch. Compare client registration/update under each group ID, full group path, and duplicate leaf name. Record which policy profile was required and which group object the evaluator resolved.

A positive is **membership in wrong group ID with matching display name -> client-policy condition passes -> marker-only client update omits a required test profile**. Do not create a broadly trusted redirect URI, privileged service account, or production client.

### IdP management versus organization management

Use two organizations, two identity providers, and roles that can manage an IdP but cannot manage organization B. Exercise link, unlink, replace, and read operations one at a time. The decisive result is **IdP-management permission -> API accepts organization B selector -> synthetic provider becomes linked to B without B-management permission**. Do not connect a real upstream IdP or influence real user login.

## Apache Atlas: enumerate admin route-family authorization drift

Use an authenticated non-admin lab user and derive candidate routes from the same Atlas build's UI traffic, OpenAPI material, and source,not from broad production guessing. Compare anonymous, ordinary user, scoped operator, and administrator decisions for each admin route. Invoke only read-only status endpoints or replace mutating handlers with no-op counters.

Capture route, method, normalized principal, groups/roles, required capability, handler reached, object selected, and response marker. A valid finding shows **authenticated non-admin -> admin route passes authorization -> no-op administrative handler is reached**. Do not alter classifications, entity metadata, users, policies, indexes, or production configuration.

## Apache Kyuubi: bind Engine UI proxy targets to an allowlist

The Engine UI route reportedly accepts host and port in the request path. Kyuubi 1.12.0 disables the proxy by default and adds an allowed-host setting when it is re-enabled. Build a local fixture with two owned HTTP listeners and no route to sensitive networks.

1. Record feature state and the exact route generated by the Kyuubi UI.
2. Compare configured listener A, unlisted listener B, hostname/IP spellings, explicit/default ports, encoded separators, redirects between the two listeners, and malformed authorities.
3. Return only listener identity and a random canary. Log parsed host, normalized authority, DNS result, redirect chain, and final peer.
4. Repeat with 1.12.0 in default-disabled mode, then re-enable it with only listener A allowlisted.

A bounded positive is **remote request -> path-selected unlisted authority -> Kyuubi connects to owned listener B**. Never probe loopback services other than your fixture, cloud metadata, RFC1918 targets, control planes, or another tenant's Engine UI.

## July 30 Kyuubi multipart filename follow-up

[GHSA-h9qj-gx4p-69cp / CVE-2026-52680](https://github.com/advisories/GHSA-h9qj-gx4p-69cp) adds a filesystem edge to Kyuubi's REST batch surface: versions 1.7.0 through 1.11.1 used the client-supplied multipart filename when creating a temporary uploaded resource. Kyuubi 1.12.0 is the fixed control.

1. Use a disposable Kyuubi instance, temporary upload root, and one empty sibling directory containing only a random marker. Do not mount credentials, Spark configuration, user homes, or production batch resources.
2. Capture a normal REST batch multipart upload from the exact version. Keep body content inert and vary only the filename: basename, nested path, dot segments, absolute temp path, encoded/mixed separators accepted by the HTTP stack, duplicate filename parameters, and a symlinked parent fixture.
3. Instrument the raw `Content-Disposition`, multipart parser output, filename normalization, intended upload root, canonical final path, create/open flags, and before/after hashes.
4. Positive evidence is **remote multipart filename -> canonical write path escapes the upload root -> inert marker file appears only in the disposable sibling directory**. Stop after one new file; never overwrite an existing path.
5. Compare 1.12.0, a server-generated basename, component-aware containment, an unrelated form field, and a request denied from the batch endpoint.

Report filename parsing, outside-root path selection, and controlled write as separate edges. Do not target configuration, startup files, authorized keys, logs, jars, or executable paths.

## WordPress calculator: prove evaluator reachability without a payload

The Cost Calculator Builder PRO record says front-end order data reaches a generated PHP formula and then `eval()`, while the required nonce is emitted publicly. It also describes a punctuation-only bypass technique; do not reproduce or publish that gadget.

In a disposable source-instrumented site, replace the evaluator with a recorder that logs the formula hash, tainted field name, and counter increment but never evaluates input. Compare a normal calculator submission, punctuation-only inert markers, omitted/invalid/public nonce states, unexpected arrays, and the corrected build. A positive is **anonymous front-end request -> `orderDetails[*].originalValue` reaches generated formula -> instrumented dynamic-evaluation sink is selected**.

Keep nonce exposure and evaluator reachability as separate edges. Static source tracing plus a no-op sink counter is sufficient; do not run PHP expressions, filesystem calls, callbacks, or process functions.

## Reporting checklist

Include:

- exact product, package/plugin slug, affected/fixed build or commit, feature state, route/CLI flags, and trust source;
- raw selector, decoded value, canonical identity/path/authority, authorization decision, and sink reached;
- synthetic principal, group/organization immutable IDs, token verification result, route role, and callback listener identity;
- before/after hashes for output tests and recorder-only evidence for process/evaluator tests;
- negative controls for omitted, malformed, wrong-issuer, wrong-audience, wrong-group-ID, wrong-role, unlisted-host, sibling-path, and fixed-build cases; and
- redaction of tokens, cookies, signing keys, credentials, callback authorities, internal topology, and real filesystem paths.

Report only the strongest proven edge. Do not inflate a no-op recorder into host compromise, a route mismatch into data access, or an owned callback into access to internal services.