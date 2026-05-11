# Config, OT, and web-admin boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11 16:17-16:24 UTC.

This batch is durable because it repeats the same control-plane lesson across OT/industrial services, config servers, and low-code/admin surfaces: an endpoint that can read, write, delegate, or configure infrastructure must treat every filename, project key, URL, token, and diagnostic log as a privilege boundary.

## Advisories covered

- **Velociraptor ACL policy disclosure** — [GHSA-3c93-g9g6-p5j4](https://github.com/advisories/GHSA-3c93-g9g6-p5j4) / CVE-2026-7573: low-privilege authenticated users could query `GetUserRoles` with chosen `Name` and `Org` values to retrieve complete ACL policies across organizations. Affects `www.velocidex.com/golang/velociraptor <0.76.5`.
- **Velociraptor EVTX parser crash** — [GHSA-6cmp-qv2f-x97x](https://github.com/advisories/GHSA-6cmp-qv2f-x97x) / CVE-2026-7572: crafted `.evtx` files could crash `parse_evtx` through off-by-one handling in `ConsumeUnit16Array` / `ConsumeUnit64Array`. Affects `www.velocidex.com/golang/velociraptor <0.76.5`.
- **Eclipse BaSyx operation-delegation SSRF** — [GHSA-gx3v-wxfj-8h24](https://github.com/advisories/GHSA-gx3v-wxfj-8h24) / CVE-2026-7412: unauthenticated delegated operations could make blind HTTP POSTs to arbitrary internal, external, or cloud-metadata targets. Affects `org.eclipse.basyx:basyx.sdk <2.0.0-milestone-10`.
- **Eclipse BaSyx Submodel file path traversal** — [GHSA-8gpm-h2mh-36qc](https://github.com/advisories/GHSA-8gpm-h2mh-36qc) / CVE-2026-7411: upload `fileName` path normalization gaps could write arbitrary files as the Java process, creating RCE paths. Affects `org.eclipse.basyx:basyx.sdk <2.0.0-milestone-10`.
- **FUXA fallback JWT secret** — [GHSA-c8m8-3jcr-6rj5](https://github.com/advisories/GHSA-c8m8-3jcr-6rj5) / CVE-2025-69971: deployments without an explicit `secretCode` used static fallback signing secret `frangoteam751`, allowing JWT forgery and auth bypass. Affects `@frangoteam/fuxa <=1.2.11`; fixed in 1.3.0. [GHSA-2r8f-cf6w-x5vq](https://github.com/advisories/GHSA-2r8f-cf6w-x5vq) is the withdrawn duplicate.
- **Dolibarr Shipments API SQL injection** — [GHSA-rvwr-q5hj-wq7g](https://github.com/advisories/GHSA-rvwr-q5hj-wq7g) / CVE-2026-7688: `fields` handling in `_checkValForAPI` for `expedition.class.php` could become SQL injection. Affects `dolibarr/dolibarr <=23.0.2`.
- **Budibase plugin URL SSRF** — [GHSA-xh5j-727m-w6gg](https://github.com/advisories/GHSA-xh5j-727m-w6gg) / CVE-2026-45061: plugin URL upload accepted a trivial `.tar.gz` substring check, allowing authenticated builders to request internal resources through `/api/plugin`. Affects `budibase <=3.34.11`.
- **Spring Cloud Config secret/log/path batch** — [GHSA-j6hh-h3cf-c2hf](https://github.com/advisories/GHSA-j6hh-h3cf-c2hf) / CVE-2026-41004 logged sensitive values at trace level; [GHSA-86wq-234q-r6wg](https://github.com/advisories/GHSA-86wq-234q-r6wg) / CVE-2026-41002 exposed the Git `basedir` to TOCTOU attacks; [GHSA-6g23-24mc-hx6x](https://github.com/advisories/GHSA-6g23-24mc-hx6x) / CVE-2026-40982 allowed path traversal when serving arbitrary text/binary files; [GHSA-2mh5-3cw6-hrrq](https://github.com/advisories/GHSA-2mh5-3cw6-hrrq) / CVE-2026-40981 could expose unintended GCP Secret Manager projects through user-controlled keys. Affects Spring Cloud Config 3.1.x through 5.0.x ranges listed in the advisories; patched in 3.1.14, 4.1.10, 4.2.7, 4.3.3, and 5.0.3 or later where available.

## Operator triage

1. Patch internet-exposed admin/control-plane services first: BaSyx, Spring Cloud Config, Budibase, FUXA, Dolibarr, and Velociraptor all sit near sensitive operational data.
2. Rotate FUXA JWT secrets and invalidate sessions if the fallback secret may have been used; assume tokens signed with the public default are forgeable.
3. Put SSRF egress policy around BaSyx operation delegation and Budibase plugin import: block link-local metadata, RFC1918 destinations, loopback, Unix sockets, and DNS-rebinding pivots before app-layer validation.
4. Move Spring Cloud Config clone directories and file-serving roots onto dedicated, non-shared, non-symlinkable paths; restrict Config Server clients to explicit app/profile/project allowlists.
5. For Velociraptor multi-org deployments, treat ACL-policy disclosure as tenant metadata exposure: audit low-privilege calls to role/ACL APIs and update collectors before processing untrusted `.evtx` evidence.

## Durable controls

- Control-plane APIs need object-level authorization on the requested tenant, organization, project, and user — not just authenticated access to the endpoint.
- URL and file extension checks are not security boundaries; canonicalize, resolve, and enforce destination policy after redirects and decompression/import decisions.
- Default secrets must be generated per deployment, stored outside images, and rotated on upgrade from static fallback behavior.
- Config servers should never log secrets at high verbosity; add CI/log scanners for token-like values and document how trace logging is safely enabled.
- Parser plugins that ingest evidence files need worker isolation and input-size/crash budgets so one malformed artifact cannot kill the operator plane.
