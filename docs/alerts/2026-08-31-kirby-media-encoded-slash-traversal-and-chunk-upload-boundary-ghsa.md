# Kirby CMS media-handler encoded-slash traversal and chunk-upload permission boundary (GHSA)

Source: GitHub Security Advisories REST API, published 2026-08-31.

These two records are durable because they expose a reusable **web-server encoded-slash differential** at a thumbnail/media-generation boundary, plus an adjacent **upload-permission timing boundary** in the same CMS. The encoded-slash pattern generalizes to any framework that joins URL-derived path segments into filesystem lookups when the front server passes `%2f` through un-decoded.

## What changed

- **Kirby media-handler path traversal via encoded slashes**, [GHSA-9vx2-j98c-p72w](https://github.com/advisories/GHSA-9vx2-j98c-p72w) / CVE-2026-75594 (CWE-22): `getkirby/cms <= 4.9.4` and `>= 5.0.0, < 5.5.2`. On servers that accept URLs containing encoded slashes (`%2f`), nginx, PHP's built-in server, Apache with `AllowEncodedSlashes` enabled, the media handler's path parsing can be driven outside the intended `media` root. Effects: (1) thumbnails can be created from and served out of arbitrary accessible directories on the server that contain a valid thumbnail job (a `.json` file with thumbnail configuration for the target asset), and (2) the handler acts as a **file-existence oracle for `.json` files anywhere on the server**. Apache default configuration and hardened servers that reject encoded slashes are not affected.
- **Kirby chunked-upload permission not checked during chunk processing**, [GHSA-67mx-6wf2-92xp](https://github.com/advisories/GHSA-67mx-6wf2-92xp) / CVE-2026-71415 (CWE-862): `getkirby/cms >= 5.0.0, < 5.5.2`. Authenticated users with `access.panel` but without `files.create`, `files.replace`, or `users.update` can still upload chunks to the temporary chunked-upload storage, because the permission check is not re-applied while chunk data is processed. Incomplete upload state accumulates in the temp directory, enabling storage exhaustion of the temporary upload path. The final permission checks on files landing in `content` or `site/accounts` were not bypassed.

## Operator triage

1. Identify CMS/media-pipeline targets whose front server passes encoded slashes through: probe for `%2f` acceptance with a harmless known path (for example an encoded variant of a known public asset) and compare status/content against the unencoded form. A difference in routing or 404 behavior indicates the differential.
2. For any thumbnail/resize/crop handler, map what filesystem join happens from URL segments and whether a per-asset job/config file (JSON, XML, or similar) is required to trigger processing. A required job file turns the handler into a bounded oracle rather than an open read primitive, scope the claim accordingly.
3. Enumerate authenticated upload routes that support chunked/multipart continuation. Test whether the permission check is applied only at final assembly versus at every chunk-write call, using a benign low-privilege account and a synthetic chunk payload.
4. Separate the two impact classes: (a) traversal-driven thumbnail generation + JSON existence oracle, and (b) authenticated chunk accumulation in a temp store. They need different evidence and different remediation owners.

## Replayable validation boundaries

### Encoded-slash routing differential probe

1. Pick two known paths on the target: one that exists (a public asset) and one that does not.
2. Send requests to each with the slash encoded (`%2f`) and unencoded, and record status, content-length, and whether the application treats the path as public static content or routes it to the media handler.
3. Vulnerable result: the encoded form reaches the application's media/handler route with the traversal material still interpretable, while the unencoded form does not (or vice versa), the server and application disagree on canonicalization.
4. Capture the exact server fingerprint (nginx/PHP-FPM/APEX/built-in), the relevant `AllowEncodedSlashes`/`merge_slashes`/`accept_path_info`-class setting where identifiable, and the handler route. Do not scan broad filesystem paths on shared or production hosts; a single known-asset differential plus one controlled traversal to a disposable canary is sufficient evidence.

### JSON-job-gated thumbnail oracle boundary

1. In an authorized lab, place a synthetic thumbnail job file (a minimal JSON with a valid thumbnail recipe) next to a benign canary asset outside the media root.
2. Request the thumbnail through the traversal path derived from the job file's location.
3. Vulnerable result: the thumbnail is generated from and served out of the canary location; the handler's existence check on the job file returns distinguishable responses for existing vs missing `.json` files (the oracle).
4. Record the oracle's distinguishing signals (status code, timing, error text) without enumerating more than the scoped set of candidate paths. Do not target configuration files, credentials, or other tenants' content; prove the boundary with your own canaries.

### Chunk-upload permission-timing canary

1. Authenticate as a low-privilege user who has panel access but no upload permission (or the scoped equivalent in the lab).
2. Begin a chunked upload with a synthetic payload and send one or two chunks; do not complete the assembly.
3. Vulnerable result: the chunk is accepted and persisted to the temporary chunk store despite the missing permission. Confirm the final assembly step still denies the low-privilege user (the advisory states content/accounts permission checks held).
4. Capture the route, method, permission matrix for the test user, the temp-store location class, and the denied final-assembly response. Never upload real user data or exceed benign marker payloads.

## Reporting heuristics

- Frame the traversal as **server-vs-application canonicalization differential at a media-generation handler**, not as a generic "path traversal." Include the `%2f` routing differential evidence, the job-file precondition, and the two effects (arbitrary-location thumbnail generation; `.json` existence oracle).
- Distinguish clearly what the oracle can and cannot do: it is bounded by the requirement of a valid thumbnail job file per target asset. Do not claim arbitrary file read of non-JSON content without demonstrating the job-file precondition is bypassable.
- Frame the chunk issue as **authorization applied only at final assembly, not at chunk write**, with the permission matrix and the denied-assembly evidence. The impact is temp-storage consumption by an authenticated low-privilege user, avoid overclaiming to file upload or content injection.
- Include the exact version ranges and the server configurations that are not affected (Apache defaults, encoded-slash rejection), so remediation triage is precise.
- The same feed wave included availability-only records (decode-uri-component DoS, Socket.IO WebTransport session-id handling DoS, Kirby chunk storage exhaustion framed as DoS) and a large batch of sparse WordPress plugin/theme records plus re-surfaced older advisories; those were reviewed and marked processed without publication.

## Sources

- GitHub Advisory Database: [GHSA-9vx2-j98c-p72w / CVE-2026-75594](https://github.com/advisories/GHSA-9vx2-j98c-p72w)
- GitHub Advisory Database: [GHSA-67mx-6wf2-92xp / CVE-2026-71415](https://github.com/advisories/GHSA-67mx-6wf2-92xp)
- Related wiki page: [Canonicalization differentials at security gates](../methodology/canonicalization-differentials-at-security-gates.md)
