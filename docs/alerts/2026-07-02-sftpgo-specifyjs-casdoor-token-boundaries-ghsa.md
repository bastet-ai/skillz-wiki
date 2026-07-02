# SFTPGo, SpecifyJS, Casdoor, and token-parser boundary checks

Source: hourly offensive-security scan, 2026-07-02. Primary entries: GitHub Advisory Database [GHSA-h64p-8h4r-6gfh](https://github.com/advisories/GHSA-h64p-8h4r-6gfh), [GHSA-3vcg-pv95-pq54](https://github.com/advisories/GHSA-3vcg-pv95-pq54), [GHSA-8882-frvv-92w4](https://github.com/advisories/GHSA-8882-frvv-92w4), [GHSA-j5qp-p44g-2m49](https://github.com/advisories/GHSA-j5qp-p44g-2m49), [GHSA-xw57-23p8-9wc5](https://github.com/advisories/GHSA-xw57-23p8-9wc5), [GHSA-5c7w-4wm3-85vw](https://github.com/advisories/GHSA-5c7w-4wm3-85vw), [GHSA-gg9x-qcx2-xmrh](https://github.com/advisories/GHSA-gg9x-qcx2-xmrh), and the Casdoor SAML/JWT set [GHSA-fwgq-j9r9-qjgr](https://github.com/advisories/GHSA-fwgq-j9r9-qjgr), [GHSA-3w4h-g9f5-j84p](https://github.com/advisories/GHSA-3w4h-g9f5-j84p), [GHSA-mfvp-7p3v-x9mh](https://github.com/advisories/GHSA-mfvp-7p3v-x9mh), [GHSA-rgq2-93gj-ffxg](https://github.com/advisories/GHSA-rgq2-93gj-ffxg), and [GHSA-339w-3hqm-9pjc](https://github.com/advisories/GHSA-339w-3hqm-9pjc).

These are durable for operators because they expose recurring validation seams: public file-share path prefixes, download content disposition, URL parser and redirect checks, GraphQL template interpolation, empty JWT keys, and SAML/OAuth assertions accepted without binding to the trusted issuer, audience, request, time window, or revocation state.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-h64p-8h4r-6gfh](https://github.com/advisories/GHSA-h64p-8h4r-6gfh) / CVE-2026-49244 | SFTPGo `>= 2.2.0, <= 2.7.1` public browsable-share partial ZIP download | client-supplied `files` entries were checked with a raw path-prefix relationship, allowing files outside the shared directory when the canonical path began with the share directory name | Public-share assessments should include sibling-prefix canaries such as `share` vs `share-private`, not only `../` traversal. |
| [GHSA-3vcg-pv95-pq54](https://github.com/advisories/GHSA-3vcg-pv95-pq54) / CVE-2026-49245 | SFTPGo public-share and user file download `inline` parameter | attacker-controlled stored files could be emitted as active `text/html` under the SFTPGo web origin instead of forced attachment | Download endpoints are render-origin boundaries; prove with harmless HTML markers and no credential theft. |
| [GHSA-8882-frvv-92w4](https://github.com/advisories/GHSA-8882-frvv-92w4) / CVE-2026-50288 | `@asymmetric-effort/specifyjs < 0.2.136` `secureFetch` | URL parse failures silently returned from validation and allowed the request path to continue | SSRF/URL guard testing must include malformed URLs and parser-error branches, not only blocked schemes. |
| [GHSA-j5qp-p44g-2m49](https://github.com/advisories/GHSA-j5qp-p44g-2m49) | SpecifyJS `secureFetch` | only the initial URL was validated before default `fetch()` redirect following | Treat redirects as a second URL authority decision; capture only owned callback hits. |
| [GHSA-xw57-23p8-9wc5](https://github.com/advisories/GHSA-xw57-23p8-9wc5) | SpecifyJS localhost checks | loopback filtering covered only `localhost` and `127.0.0.1`, missing forms such as `0.0.0.0`, `[::1]`, and the broader `127.0.0.0/8` range | URL allowlist tests should include numeric, IPv6, and alias loopback forms. |
| [GHSA-5c7w-4wm3-85vw](https://github.com/advisories/GHSA-5c7w-4wm3-85vw) | SpecifyJS `gql` template tag | interpolated strings containing GraphQL metacharacters warned but were still concatenated into the query | GraphQL template helpers need variable binding; test interpolation sinks with schema-safe canary fields. |
| [GHSA-gg9x-qcx2-xmrh](https://github.com/advisories/GHSA-gg9x-qcx2-xmrh) / CVE-2026-49852 | `joserfc <= 1.6.7` HMAC JWT verification | HS256/HS384/HS512 verification can accept attacker-forged tokens when the caller supplies `None` or an empty string as the key | Token-parser tests should include unset-env and empty-key failure modes with disposable tokens only. |
| [GHSA-fwgq-j9r9-qjgr](https://github.com/advisories/GHSA-fwgq-j9r9-qjgr) / CVE-2026-9090 | Casdoor SAML certificate handling | incoming SAMLResponse certificate material could be trusted instead of the preconfigured IdP certificate | Identity-provider assessments should verify the accepted signing key is the configured trust anchor, not assertion-supplied material. |
| [GHSA-3w4h-g9f5-j84p](https://github.com/advisories/GHSA-3w4h-g9f5-j84p) / CVE-2026-9093 | Casdoor SAML audience validation | `AudienceRestriction` was not enforced for the Casdoor SP | Test cross-SP assertion replay with lab-only IdPs and synthetic users. |
| [GHSA-mfvp-7p3v-x9mh](https://github.com/advisories/GHSA-mfvp-7p3v-x9mh) / CVE-2026-9098 | Casdoor `/api/acs` callback | well-formed unsolicited SAML responses could be accepted without matching a prior AuthnRequest | Capture request/response binding decisions, not just successful login state. |
| [GHSA-rgq2-93gj-ffxg](https://github.com/advisories/GHSA-rgq2-93gj-ffxg) / CVE-2026-9096 | Casdoor SAML time validation | library time-bound warnings were computed but ignored before issuing a session | SAML harnesses should include expired and not-yet-valid assertion controls. |
| [GHSA-339w-3hqm-9pjc](https://github.com/advisories/GHSA-339w-3hqm-9pjc) / CVE-2026-9097 | Casdoor OAuth token exchange | JWT subject tokens were signature-validated without checking active/revoked state | Token-exchange tests should include revoked canary tokens and state-table evidence. |

## Replayable validation boundaries

### SFTPGo public-share path and render-origin checks

- Preconditions: disposable SFTPGo lab, affected version, a public browsable share, synthetic files only, and no real user home directories, keys, backups, or customer uploads.
- For the partial ZIP path boundary, create one shared directory such as `/tmp/sftpgo-lab/share` and a sibling canary path such as `/tmp/sftpgo-lab/share-private/marker.txt`. Request a partial ZIP using only a marker filename/path that should remain confined to the public share.
- Positive evidence: the ZIP includes the sibling marker even though it is outside the public share. Stop at the canary file; do not enumerate directories or request system files.
- For the `inline` render boundary, place a harmless HTML file containing only a visible marker, then compare normal download behavior with any `inline` parameter path. Positive evidence is same-origin HTML rendering; do not run credential collection, JavaScript exfiltration, or account-pivot payloads.
- Negative controls: SFTPGo `>= 2.7.3`, directory-boundary-aware realpath checks, and unconditional `Content-Disposition: attachment` for untrusted files.

### SpecifyJS URL and GraphQL guard harness

- Preconditions: local SpecifyJS app or unit harness, owned callback endpoint, fake secrets, no internal network targets, and a version before `0.2.136` for vulnerable controls.
- Build a decision table for `secureFetch`: valid HTTPS URL, malformed URL that triggers `new URL()` failure, `https://owned.example/redirect-to-http`, `https://owned.example/redirect-to-loopback`, `http://127.1/`, `http://0.0.0.0/`, and `http://[::1]/`.
- Positive evidence: a malformed URL or redirect/loopback variant proceeds when policy claims it should be rejected. Use only owned callbacks or loopback canary services; never probe cloud metadata, cluster APIs, admin panels, or production intranet hosts.
- For `gql`, interpolate a synthetic value containing GraphQL metacharacters into a query helper and record whether the final query string is constructed. Positive evidence can be a schema-safe marker field or rejected/accepted decision table; do not query tenant data.
- Negative controls: parser errors throw, redirects are rejected or revalidated after every hop, loopback/private-IP canonicalization is complete, and GraphQL user values are passed only through variables.

### joserfc empty-key JWT verification check

- Preconditions: isolated Python harness using `joserfc <= 1.6.7`, a disposable token issuer/verifier, and no production JWT secrets.
- Simulate common misconfiguration paths separately: unset environment variable resolved to `None`, empty environment variable resolved to `""`, missing DB/Redis key fallback, and a valid non-empty key.
- Generate a canary HS256 token signed with `HMAC(key=b"")` and synthetic claims such as `sub=skillz-empty-key-canary`.
- Positive evidence: the verifier accepts the canary token when the application-provided key is `None` or empty. Negative evidence should show the same token rejected with a real key and on a patched or application-hardened verifier.
- Do not attempt to forge production sessions, admin roles, SSO tokens, or third-party JWTs.

### Casdoor SAML/OAuth assertion-binding harness

- Preconditions: lab Casdoor instance, lab IdP, disposable SP configuration, synthetic users, fake signing keys, and no production tenant metadata or sessions.
- Build a decision table for SAML assertions: signed by configured IdP certificate, signed by assertion-supplied attacker certificate, wrong `AudienceRestriction`, expired `NotOnOrAfter`, future `NotBefore`, unsolicited response without a recorded AuthnRequest, and response replay after the flow ends.
- Positive evidence: Casdoor issues a lab session for the wrong signing key, wrong audience, invalid time window, unsolicited response, or replayed response.
- For token exchange, mint a disposable subject token, revoke or invalidate it in the lab token table, then attempt exchange. Positive evidence is exchange success after revocation.
- Stop at lab session issuance and decision tables. Do not access real applications, real tenants, customer identity data, or session cookies.

## Reporting notes

- Lead with the crossed boundary: **public share path to outside-share read**, **stored file to same-origin HTML render**, **URL parser/redirect to unvalidated fetch**, **GraphQL interpolation to query construction**, **empty JWT key to forged token acceptance**, or **SAML/JWT assertion to unbound login/token exchange**.
- Include affected package/version, route or helper, canary-only request details, normalized path/URL/assertion fields, decision table, and fixed-version negative control.
- Keep evidence synthetic. Avoid reading secrets, files outside disposable canary directories, tenant GraphQL data, production identity metadata, live tokens, or user sessions.

## Reviewed but not promoted here

- [GHSA-2944-57xv-2682](https://github.com/advisories/GHSA-2944-57xv-2682) is a SpecifyJS `data:` URI size limit issue and was not promoted as a standalone workflow because it is resource-exhaustion focused.
- [GHSA-qcr8-x557-7cp3](https://github.com/advisories/GHSA-qcr8-x557-7cp3) covers production console warnings leaking framework state; useful for code hygiene, but it did not add a distinct replayable operator path.
- [GHSA-93q6-wwjh-jc6h](https://github.com/advisories/GHSA-93q6-wwjh-jc6h) is a legacy-browser CSS expression sanitizer bypass; note it during render reviews, but modern-browser exploitability is narrow.
- [GHSA-3vcg-pv95-pq54](https://github.com/advisories/GHSA-3vcg-pv95-pq54) is included only as a render-origin boundary paired with SFTPGo shares; do not overstate it as cookie theft because the advisory notes HttpOnly and session-cookie constraints.
