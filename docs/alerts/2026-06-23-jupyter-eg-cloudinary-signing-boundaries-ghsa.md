# Jupyter Enterprise Gateway and Cloudinary signing boundary checks

Source: hourly offensive-security scan, 2026-06-23. Primary entries: GitHub advisories [GHSA-chq7-94j8-cj28](https://github.com/advisories/GHSA-chq7-94j8-cj28) and [GHSA-h5x8-xp6m-x6q4](https://github.com/advisories/GHSA-h5x8-xp6m-x6q4).

This batch is durable because both issues expose reusable validation patterns for operator-controlled values crossing into privileged runtime decisions: notebook kernel environment variables becoming Kubernetes security context IDs, and low-privilege CMS users obtaining server-signed Cloudinary upload parameters.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-chq7-94j8-cj28](https://github.com/advisories/GHSA-chq7-94j8-cj28) | Jupyter Enterprise Gateway `ContainerProcessProxy` | user-supplied `KERNEL_UID` / `KERNEL_GID` strings were checked against prohibited ID strings before later template rendering parsed them as integers | Notebook gateway reviews should test string-normalization gaps between admission checks and pod manifests; prove only with disposable kernels in an owned Kubernetes lab. |
| [GHSA-h5x8-xp6m-x6q4](https://github.com/advisories/GHSA-h5x8-xp6m-x6q4) | `@jhb.software/payload-cloudinary-plugin` client-upload signing endpoint | authenticated Payload users could send arbitrary `paramsToSign` to a server-side Cloudinary signing helper without parameter allowlists or folder/public-id policy enforcement | CMS media-upload reviews should test whether signing or presign endpoints bind caller intent to server policy; prove with disposable Cloudinary assets and inert webhook callbacks only. |

## Operator triage

1. **Identify caller-controlled runtime fields.** For Jupyter, collect the kernel launch API, allowed kernels, and which `env` keys users can set. For Cloudinary, collect the CMS role needed to call the signing endpoint and the exact upload parameters accepted from the browser.
2. **Compare validation form to execution form.** Look for string comparisons, allowlists, or blacklists that run before whitespace trimming, type coercion, template rendering, URL parsing, folder normalization, or cloud-provider upload handling.
3. **Keep proofs disposable.** Use lab namespaces, one-off kernels, synthetic UID/GID values, throwaway Cloudinary folders, harmless marker files, and owned callback URLs.
4. **Avoid secret and tenant data.** Do not inspect real notebooks, datasets, model files, cloud credentials, customer media libraries, private assets, or production webhook receivers.
5. **Capture parity evidence.** Strong reports show vulnerable and patched behavior for accepted/rejected kernel IDs, signed parameter sets, resulting upload options, and role boundaries.

## Replayable validation boundaries

### Jupyter Enterprise Gateway kernel-ID harness

- Preconditions: owned Jupyter Enterprise Gateway deployment, Kubernetes-backed kernels, permission to launch test kernels, disposable namespace, and no shared production workloads.
- Send a negative-control kernel launch with `KERNEL_UID` and `KERNEL_GID` set exactly to a prohibited value such as `0`; record the expected denial.
- Send normalization variants that should be semantically equivalent after parsing, such as trailing/leading whitespace around the same numeric value. Evidence is whether the admission layer accepts the launch and whether the rendered pod security context resolves to the prohibited numeric ID.
- Stop after proving the scheduling and identity boundary with a disposable kernel. Do not mount host paths, read service-account tokens, inspect notebooks, or attempt cluster escape.
- Negative controls: canonicalize IDs before comparison, parse to integers before policy checks, reject non-canonical numeric strings, and enforce Kubernetes admission policies independent of Enterprise Gateway input validation.

### Cloudinary signing-policy harness

- Preconditions: owned Payload CMS lab, `@jhb.software/payload-cloudinary-plugin` with client uploads enabled, a low-privilege authenticated test user, and a disposable Cloudinary cloud/folder.
- Call the signing endpoint with a normal browser-style upload parameter set and verify baseline behavior.
- Repeat with canary-only parameters that should be server-owned or policy-bound, for example alternate folders, marker `public_id` values, `overwrite`, `type`, `invalidate`, or a `notification_url` pointing to an owned callback collector.
- Use the returned signature only against disposable assets in the test Cloudinary account. Evidence is the signed parameter set, the resulting upload decision, and callback receipt for the owned URL if notification signing is in scope.
- Negative controls: endpoint role checks, strict parameter allowlists, server-derived folder/public-id prefixes, timestamp freshness, overwrite/type/invalidation restrictions, and callback URL allowlists.

## Reporting notes

- Lead with the crossed boundary: **kernel launch env string to Kubernetes UID/GID**, or **authenticated CMS user to arbitrary Cloudinary upload signature**.
- Include route, required role, version, raw request parameters, normalized/executed values, and patched-vs-vulnerable decision tables.
- Keep evidence boring: pod identity from a disposable kernel, marker asset IDs, owned callback logs, and rejected-control screenshots or response bodies.
- Never include production notebook contents, cluster tokens, customer media, real Cloudinary secrets, or payloads that overwrite valuable assets.
