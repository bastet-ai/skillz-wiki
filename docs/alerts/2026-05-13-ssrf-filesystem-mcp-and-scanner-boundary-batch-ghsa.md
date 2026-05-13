# SSRF, filesystem, MCP, and scanner-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

The durable lesson is to bind network, file, and scanner helpers to a resolved target after canonicalization; deny-lists and root paths fail when checks run before redirects, symlinks, IPv6 literals, backup restore, or package metadata are resolved.

## Advisories covered

- **django-s3file relative path traversal** — [GHSA-67qg-7284-2277](https://github.com/advisories/GHSA-67qg-7284-2277): relative paths could escape intended object/file locations.
- **ciguard symlink escape** — [GHSA-8cxw-cc62-q28v](https://github.com/advisories/GHSA-8cxw-cc62-q28v): pipeline discovery followed symlinks out of the scan root.
- **ciguard container runs as root** — [GHSA-jrm4-4pcf-4763](https://github.com/advisories/GHSA-jrm4-4pcf-4763): scanner container defaults increased blast radius because no USER directive lowered privilege.
- **OpenTelemetry OTLP disk retry local blob injection** — [GHSA-4625-4j76-fww9](https://github.com/advisories/GHSA-4625-4j76-fww9): default temp-path behavior let local users inject retry blobs.
- **changedetection.io backup-restore file read** — [GHSA-8757-69j2-hx56](https://github.com/advisories/GHSA-8757-69j2-hx56): crafted backup restore could read arbitrary local files.
- **ssrfcheck incomplete SSRF deny-list** — [GHSA-j4rj-2jr5-m439](https://github.com/advisories/GHSA-j4rj-2jr5-m439): the SSRF checker missed disallowed inputs and should not be treated as an oracle.
- **requests-hardened SSRF bypass** — [GHSA-vh75-fwv3-pqrh](https://github.com/advisories/GHSA-vh75-fwv3-pqrh): hardened client checks were incomplete under URL/address edge cases.
- **Langflow Knowledge Bases path traversal** — [GHSA-9whx-c884-c68q](https://github.com/advisories/GHSA-9whx-c884-c68q): knowledge-base file APIs could cross path boundaries.
- **open-websearch MCP SSRF** — [GHSA-v228-72c7-fx8j](https://github.com/advisories/GHSA-v228-72c7-fx8j): bracketed IPv6 literals and non-resolving hostname checks bypassed private/local filtering.

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

