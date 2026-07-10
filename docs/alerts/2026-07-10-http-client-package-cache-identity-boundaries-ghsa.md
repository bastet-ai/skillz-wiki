---
title: HTTP client, package cache, and identity-boundary checks from July 10 GHSA updates
---

# HTTP client, package cache, and identity-boundary checks from July 10 GHSA updates

This update promotes late July 9 / early July 10 GHSA records into reusable operator checks for authorized assessments. The shared pattern is caller-controlled protocol, artifact, package, or identity metadata crossing a trusted boundary after a library or platform has already decided the operation is safe: redirect-following clients forward credentials, multipart builders serialize unescaped header material, package metadata becomes a filesystem path, smart-object filenames drive extraction paths, and cross-organization tokens are exchanged without rebinding the user to the target application.

Sources:

- [GHSA-9m9w-gxf7-rh8m / CVE-2026-48595: Tesla `FollowRedirects` leaks `Authorization` on cross-origin redirects via case-sensitive filtering](https://github.com/advisories/GHSA-9m9w-gxf7-rh8m)
- [GHSA-28jh-g32x-v9v4 / CVE-2026-48598: Tesla multipart `Content-Disposition` values allow part/header smuggling](https://github.com/advisories/GHSA-28jh-g32x-v9v4)
- [GHSA-q7jx-v53g-848w / CVE-2026-48596: Tesla multipart `Content-Type` parameters allow CRLF header injection](https://github.com/advisories/GHSA-q7jx-v53g-848w)
- [GHSA-h74c-q9j7-mpcm / CVE-2026-48597: Tesla Mint adapter interns untrusted URL schemes as BEAM atoms](https://github.com/advisories/GHSA-h74c-q9j7-mpcm)
- [GHSA-2rmg-vrx8-9j2f / CVE-2026-49836: `psd-tools` smart-object filenames can write outside the extraction root](https://github.com/advisories/GHSA-2rmg-vrx8-9j2f)
- [GHSA-h672-p7h7-97v9 / CVE-2026-53956: `rattler_cache` / `py-rattler` package cache traversal through conda build strings](https://github.com/advisories/GHSA-h672-p7h7-97v9)
- [GHSA-h5g6-xmh4-hc37 / CVE-2026-55252: OpenRun redirect validation bypass with network-path references](https://github.com/advisories/GHSA-h5g6-xmh4-hc37)
- [GHSA-c9w5-qp6m-m395 / CVE-2026-9094: Casdoor token exchange misses cross-organization binding](https://github.com/advisories/GHSA-c9w5-qp6m-m395)
- [GHSA-9vcr-p3rj-q5q6 / CVE-2026-49834: `sigstore-go` multi-log threshold counted witnesses instead of log authorities](https://github.com/advisories/GHSA-9vcr-p3rj-q5q6)

!!! warning "Authorized validation only"
    Keep proofs in disposable HTTP-client harnesses, upload/extraction sandboxes, owned package indexes/channels, lab identity realms, and fake signing infrastructure. Use fake bearer tokens, owned redirectors, inert multipart fields, marker-only PSD/conda package files, synthetic users and organizations, and disposable trust roots. Do not capture live credentials, hit internal services, write outside lab-owned temp directories, exchange real user tokens, or weaken production supply-chain verification.

## Operator use

Use these checks when a scope includes:

- Elixir services using Tesla for webhook relays, link previews, OAuth/OIDC discovery, file uploads, API integrations, or redirect-following fetches;
- multipart client builders that accept user-controlled filenames, field names, disposition parameters, content-type parameters, or charset values;
- image/design-processing pipelines that extract PSD smart objects or save embedded files from untrusted creative assets;
- conda-compatible package managers, private channels, build caches, or CI workers that consume repository-controlled `repodata`;
- login, invite, callback, or referrer flows that validate a redirect as same-origin but then redirect to the path component alone;
- Casdoor or similar multi-organization identity brokers that exchange JWTs for application tokens;
- signature-verification harnesses where a policy claims multiple independent transparency logs are required.

## Recon checklist

| Boundary | What to look for | Safe canary |
| --- | --- | --- |
| Redirected credentials | Redirect middleware that strips `authorization` only by case-sensitive header name or preserves `Host` variants | Fake `Authorization: Bearer canary` header to an owned first hop that redirects to an owned second hop |
| Multipart header serialization | Filenames, field names, disposition opts, or `Content-Type` params serialized into HTTP headers without quote, semicolon, CR, or LF rejection | Harmless multipart request captured by a local test server; no upstream production service |
| URL scheme normalization | Fetchers passing untrusted URL schemes through atom/string interning or adapter dispatch before allow-list validation | Small fixed set of bogus schemes in a local harness; do not run exhaustion loops |
| Smart-object extraction | PSD embedded-object names used as default output filenames or external smart-object paths opened directly | Synthetic PSD fixture and marker path under a lab temp directory |
| Conda cache materialization | Package record `build`, name, version, subdir, or archive metadata joined into cache paths without final-root checks | Owned test channel and package with a marker build string in a disposable cache |
| Network-path redirects | Validation checks full same-origin URL, then redirects only to a path that may begin with `//host` or encoded equivalents | Owned redirect target and a browser/client decision table |
| Token exchange tenant binding | JWT signature is valid, but user organization/tenant is not checked against the target application/client | Two synthetic organizations, disposable users, and fake app tokens |
| Multi-log threshold semantics | Verification policy counts entries, paths, or SCTs rather than distinct log authorities | Local fake log authorities and unsigned/inert test artifacts only |

## Validation patterns

### Tesla redirect credentials and multipart protocol boundaries

The Tesla advisories are useful for any assessment where a server-side HTTP client turns user, tenant, or third-party data into outbound requests.

1. Build a local harness with two owned origins: `origin-a` returns a 302 to `origin-b`; `origin-b` records only fake headers and request framing.
2. Send the request through the application code path that uses Tesla redirect following. Include both lowercase and canonical-case fake headers, for example `authorization` and `Authorization` with canary values.
3. Record whether sensitive headers cross host, scheme, or port changes. A strong proof is a table of redirect type vs leaked fake header, not a real token capture.
4. For multipart flows, pass only inert filename, field-name, and content-type-parameter canaries that contain quotes, semicolons, or CRLF-like test strings. Capture raw bytes on a local listener and show whether extra part parameters or headers appear.
5. For URL schemes, test allow-list order with a small fixed set of bogus schemes. Do not attempt atom-table exhaustion; the finding is **untrusted scheme -> atom/adapter dispatch before scheme allow-list**, not process crash.

Report these as separate boundaries: **cross-origin redirect -> credential forwarding**, **multipart value -> request header/part smuggling**, **content-type parameter -> CRLF request header injection**, and **URL scheme -> permanent atom creation before validation**.

### PSD smart-object path traversal

Design-file ingestion often trusts embedded filenames because the parser has already accepted the outer file. Treat every embedded object name as an archive-entry path.

1. In a disposable workspace, run the exact extraction path used by the target product: preview worker, asset converter, CLI helper, or upload post-processor.
2. Use a synthetic PSD fixture with one embedded object whose filename attempts an absolute or `../` path to a lab-owned sibling directory.
3. Confirm whether `SmartObject.save()` or product wrapper code writes outside the intended output root. Evidence should be pre/post file existence for a marker file only.
4. If external-kind smart objects are in scope, keep read tests to a file you placed yourself, then route the content to a controlled marker output. Never read application config, home directories, SSH keys, cloud credentials, or customer assets.

A good report says **PSD smart-object filename -> default save path -> outside-root marker write** and includes the extraction root, effective user, and patched negative control.

### Conda channel metadata to package-cache path

The `rattler_cache` advisory is a package-manager trust-boundary check: a repository/channel record that looks like metadata becomes part of a local filesystem path during cache materialization.

1. Use an owned conda channel or local static channel fixture. Do not point production CI at an untrusted public channel for testing.
2. Publish or simulate `repodata` where a package record has a build string containing traversal syntax or path separators.
3. Install or cache the package into a disposable cache root and check only for lab-owned marker paths outside that root.
4. Capture the normalized path decision: package record fields, intended cache root, computed cache key/path, and final write location.

Keep the proof to **untrusted channel metadata -> cache path join -> outside-cache write**. Do not overwrite shell startup files, package-manager config, credentials, or shared runner paths.

### Network-path redirect validation bypass

OpenRun's `//host` bypass is a compact browser/client parser-differential pattern and belongs with return-URL testing.

1. Find routes that validate a full URL's scheme and host, then later use only `URL.Path`, `redirect_to`, `Referer`, or a decoded callback value for the actual redirect.
2. Test path values that begin with `//owned.example`, `%2f%2fowned.example`, backslash variants, and mixed decoded/encoded separators.
3. Use an owned destination and record status code, `Location`, and actual browser navigation.
4. Do not combine the redirect with credential capture. The authorized proof is **same-origin validation -> path-only redirect -> browser treats network-path reference as external authority**.

### Casdoor token exchange organization binding

Token exchange bugs are most useful when reported as tenant-binding failures, not generic authentication bypass.

1. Create two synthetic organizations and two disposable users in a lab Casdoor deployment.
2. Obtain a valid JWT for a user in organization A and attempt token exchange for an application/client in organization B.
3. Record only token metadata needed to prove the mismatch: source org, target app org, user ID prefix, scopes/audience, and response decision. Redact token bodies.
4. Compare with a patched or policy-enforced negative control where signature validity is not enough unless the user belongs to the target app's organization.

Report as **valid JWT signature -> token exchange -> missing source-user to target-application organization check**.

### Sigstore multi-log threshold authority counting

Use this only for lab verification policy reviews where the program owner explicitly wants supply-chain validation testing.

1. Build a local verifier harness with fake transparency-log or CT-log authorities and a policy that claims `N > 1` independent logs are required.
2. Attempt to satisfy the threshold with multiple entries, paths, or SCTs from the same fake authority.
3. Evidence should show whether the verifier counts distinct log authorities or merely counts verified witnesses.
4. Do not test against production Rekor/CT infrastructure or real release artifacts. Use inert artifacts and disposable keys.

The operator lesson is **policy says multiple independent logs -> verifier counts same authority multiple times -> threshold bypass**.

## Reporting notes

Lead with the failed trust boundary:

- **redirect-following HTTP client -> case-sensitive header filter -> fake credential relay**;
- **multipart parameter -> raw header serialization -> protocol smuggling**;
- **untrusted URL scheme -> adapter normalization before allow-list -> process-level resource risk**;
- **embedded PSD filename -> default extractor path -> outside-root write**;
- **conda package metadata -> cache key/path -> outside-cache write**;
- **same-origin URL validation -> path-only `Location` -> network-path external redirect**;
- **signed JWT -> token exchange -> missing organization binding**;
- **multi-log policy -> per-entry counting -> single-authority threshold satisfaction**.

Include version, route/tool/library path, required attacker control, lab harness design, synthetic canary evidence, and a negative control. Avoid claiming production token theft, internal SSRF, arbitrary file overwrite, or supply-chain compromise unless the authorized lab evidence reaches that exact sink without sensitive data or irreversible side effects.
