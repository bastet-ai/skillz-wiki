# Identity, auth, and control-plane boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

Authentication and control-plane advisories are durable when a single trusted header, directory response, OAuth link, or admin route can silently change who the system believes the actor is.

## Advisories covered

- **Lemur LDAP filter injection privilege escalation** — [GHSA-3r34-vq8m-39gh](https://github.com/advisories/GHSA-3r34-vq8m-39gh): post-auth LDAP filter construction let identity attributes influence privilege decisions.
- **Lemur LDAP TLS verification disabled globally** — [GHSA-vr7c-r5gj-j3w5](https://github.com/advisories/GHSA-vr7c-r5gj-j3w5): LDAP_USE_TLS could disable certificate verification instead of tightening transport trust.
- **wger cross-tenant password reset** — [GHSA-mhc8-p3jx-84mm](https://github.com/advisories/GHSA-mhc8-p3jx-84mm): gym=None handling enabled cross-tenant reset and plaintext disclosure.
- **ArcadeDB cross-database authorization bypass** — [GHSA-fxc7-fm93-6q77](https://github.com/advisories/GHSA-fxc7-fm93-6q77): database isolation and newly-created database security defaults could be bypassed.
- **PocketBase OAuth2 account pre-hijacking** — [GHSA-pq7p-mc74-g65w](https://github.com/advisories/GHSA-pq7p-mc74-g65w): unverified-to-verified autolinking upgraded attacker-controlled identity state.
- **Ethyca Fides duplicate-detection verification bypass** — [GHSA-qx5f-ghc2-7g5c](https://github.com/advisories/GHSA-qx5f-ghc2-7g5c): privacy request identity proofing could be bypassed by duplicate detection behavior.
- **DevGuard X-Admin-Token identity assertion** — [GHSA-2g9v-7mr5-fgjg](https://github.com/advisories/GHSA-2g9v-7mr5-fgjg): an unauthenticated header could assert administrative identity.
- **Kubewarden RBAC reconnaissance** — [GHSA-wqcw-g35j-j578](https://github.com/advisories/GHSA-wqcw-g35j-j578): unchecked can_i host capability calls could disclose authorization surface.
- **parse-server MFA SMS OTP replay race** — [GHSA-jpq4-7fmq-q5fj](https://github.com/advisories/GHSA-jpq4-7fmq-q5fj): concurrent login accepted the same one-time password twice.
- **YAFNET pre-handler admin bypass to RunSql** — [GHSA-xhw7-j96h-c3g5](https://github.com/advisories/GHSA-xhw7-j96h-c3g5): admin page authorization happened too late, enabling blind SQL execution.
- **Apache Artemis missing auth** — [GHSA-fw88-pf9m-p947](https://github.com/advisories/GHSA-fw88-pf9m-p947): critical broker functions were reachable without required authentication.

## Operator triage

1. Patch affected packages and hosted services first where the vulnerable component is internet-facing, tenant-facing, or reachable by untrusted project data.
2. Inventory transitive exposure; many of these bugs live in helpers, plugins, middleware, scanner images, or framework defaults rather than application code.
3. Search logs for boundary probes: encoded paths, unusual headers, oversized bodies, duplicate auth attempts, symlinked project files, private-network URLs, and stored HTML/script payloads.
4. Add regression tests at the trust boundary, not only at the direct vulnerable function. Exercise canonicalized paths, redirects, alternate address syntax, concurrent auth, and malformed protocol inputs.

## Durable controls

- Canonicalize once, authorize after canonicalization, and execute/use only the canonicalized object.
- Give every parser, helper, cache, upload, range handler, and HTTP client explicit byte, item, time, and recursion budgets.
- Treat user-controlled templates, package metadata, project files, identity headers, event fields, and backup archives as untrusted code-adjacent inputs.
- Prefer positive allowlists tied to resolved identities/resources over deny-lists tied to raw input strings.

