---
title: Rich-text import SSRF testing
---

# Rich-text import SSRF testing

Use this when a CMS, page builder, document importer, HTML-to-PDF renderer, or WYSIWYG widget accepts HTML and rewrites embedded media by fetching it server-side. The durable bug-hunting pattern is: user-controlled markup crosses into an image/import/render pipeline, the backend resolves relative URLs against a supplied base URL, validates the URL, fetches the result, then stores, re-hosts, or embeds fetched bytes.

!!! warning "Authorized testing only"
    Run these checks only on systems where you have explicit permission. Keep targets to your own callback host, owned lab services, and in-scope internal canaries provided by the program. Do not probe cloud metadata, loopback admin panels, or private services unless the rules of engagement explicitly allow it.

## Why this matters

GitHub advisory [GHSA-pr28-mf3q-qpg6 / CVE-2026-45012](https://github.com/advisories/GHSA-pr28-mf3q-qpg6) showed this shape in ApostropheCMS: an authenticated rich-text widget validation endpoint accepted an `import.html` value containing an image, resolved the `src` with `new URL(src, import.baseUrl || baseUrl)`, fetched it server-side, and imported image-compatible responses into Apostrophe's attachment pipeline.

GitHub advisory [GHSA-983w-rhvv-gwmv / CVE-2025-68616](https://github.com/advisories/GHSA-983w-rhvv-gwmv) exposed the same operator seam in WeasyPrint's `default_url_fetcher`: an application-level `url_fetcher` could validate the initial URL, then the underlying fetch layer followed an HTTP redirect to a destination that was not revalidated. Treat server-side renderers as URL-fetch pipelines with **per-hop** authority decisions, not one-time string filters.

That is more useful than a one-off product advisory because the same pattern appears in many CMS/editor features:

- paste-from-URL and paste-from-Word/HTML import;
- page-builder widget validation or preview APIs;
- avatar, OpenGraph, favicon, media-library, and attachment import helpers;
- Markdown/HTML-to-PDF previewers that rewrite or embed images, CSS, fonts, and linked resources;
- migration tools that ingest remote HTML and localize assets.

## Inputs

- An authenticated low-privilege account that can create, edit, preview, validate, or import rich-text content.
- A controlled callback endpoint that logs method, path, headers, timing, and request body size.
- A tiny valid image file, such as a 1x1 PNG, hosted on the callback server.
- A list of in-scope editor/import endpoints from normal application traffic.
- Written authorization before attempting internal reachability checks.

## Find candidate endpoints

Look for requests that contain both widget/editor metadata and imported HTML:

```text
POST /api/*/validate-widget
POST /api/*/preview
POST /api/*/import
POST /admin/*/media/import
POST /graphql  # mutations that validate blocks, widgets, or rich text
```

In captured JSON or multipart bodies, prioritize fields named:

```text
html
content
body
import.html
import.baseUrl
baseUrl
sourceUrl
src
url
widgets
blocks
area
attachments
```

The strongest candidates parse HTML and also return image IDs, attachment IDs, rewritten media URLs, thumbnail paths, or validation errors mentioning image processing.

## Safe callback proof

Start with an external callback you control. Serve a known image and unique path per attempt:

```bash
mkdir -p /tmp/import-ssrf
base64 -d > /tmp/import-ssrf/proof.png <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+y1n0AAAAASUVORK5CYII=
EOF
python3 -m http.server 7777 --directory /tmp/import-ssrf
```

Submit HTML that references the image:

```html
<p>proof</p><img src="https://callback.example/proof-<run-id>.png">
```

If the importer supports a separate base URL, test both absolute and relative forms:

```json
{
  "import": {
    "baseUrl": "https://callback.example/assets/",
    "html": "<img src=\"proof-<run-id>.png\">"
  }
}
```

Record proof only when your callback logs a server-side request that cannot be explained by your browser loading the image. Useful separators:

- use a callback hostname that your browser never loads directly;
- put the image URL only inside the API payload, not in rendered page HTML;
- compare callback `User-Agent`, source IP/ASN, and timing to the submitted request;
- repeat with a new random path and confirm the request follows the server action.

## Redirect revalidation harness

Use this when the target claims to block private or loopback destinations before server-side rendering/fetching.

Preconditions: an owned redirector, an owned external callback endpoint, and explicit authorization before using any internal canary. Do not aim redirects at cloud metadata, admin panels, Kubernetes APIs, databases, or production intranet hosts.

Set up two controlled URLs:

```text
https://redirector.example/to-external-canary -> 302 https://callback.example/proof-<run-id>.png
https://redirector.example/to-approved-internal-canary -> 302 http://127.0.0.1:<approved-canary-port>/proof.png
```

Submit the first URL through the renderer/importer and confirm the callback proves server-side redirect following. Only then, if the rules of engagement allow it, use a program-provided internal canary for the second URL.

Positive evidence is a decision-table mismatch:

| Input | Expected policy | Observed behavior |
| --- | --- | --- |
| Direct blocked URL | rejected before fetch | rejected |
| Allowed URL that redirects to blocked URL | rejected after redirect revalidation | fetched or attempted |
| Allowed URL that redirects to owned external canary | fetched | callback hit |

Capture the redirect chain, normalized destination, status code, and whether the renderer stored or exposed fetched bytes. Stop at canary reachability; do not enumerate ports or fetch real internal resources.

## Exfiltration check for image-compatible responses

Some importers store and re-host fetched images. This turns blind SSRF into response exfiltration for image-compatible content.

After the callback fires, inspect the API response for:

```text
imageId
imageIds
attachmentId
url
src
thumbnail
rehosted media path
```

Then fetch the generated media URL from the application and compare the bytes or image dimensions to your controlled file. Keep the proof benign: a 1x1 PNG with a unique color or embedded non-sensitive marker is enough.

Report the distinction clearly:

- **Blind SSRF:** callback received a request, but the response was not exposed.
- **Semi-blind SSRF:** status, timing, size, or processing error leaked reachability.
- **Non-blind/exfiltrating SSRF:** fetched bytes were stored or re-hosted and could be retrieved through the app.

## Authorized internal reachability checks

Only do this when the scope explicitly permits internal SSRF validation. Prefer program-provided canaries over real infrastructure.

Use low-risk probes:

```text
http://127.0.0.1:<approved-canary-port>/proof.png
http://localhost:<approved-canary-port>/proof.png
http://[::1]:<approved-canary-port>/proof.png
http://10.0.0.10:<approved-canary-port>/proof.png
```

For rough port discovery, use per-port random paths and measure differences in:

- callback or collaborator hits;
- API response time;
- importer error class;
- stored-media success/failure;
- returned byte count or image-processing errors.

Avoid dangerous targets such as metadata services, admin APIs, unauthenticated databases, cloud credentials endpoints, or anything outside the rules of engagement.

## Bypass variants worth testing

If the application claims to filter private destinations, validate the filter at the same layer that performs the fetch:

- relative `src` resolved against attacker-controlled `baseUrl`;
- redirects from an allowed host to a blocked range;
- DNS rebinding or changed A/AAAA records between validation and fetch;
- IPv6 loopback and IPv4-mapped IPv6 forms;
- decimal, octal, hexadecimal, or shortened IPv4 notations;
- mixed-case schemes and whitespace/control-character normalization;
- protocol-relative URLs such as `//host/path`;
- multiple images where only the first URL is validated;
- thumbnail or metadata extraction paths that refetch after initial validation.

Document which variants were tested and which were intentionally not attempted because they were out of scope.

## Reporting heuristic

A strong report includes:

1. The exact role/permission required to reach the importer.
2. The endpoint and JSON/form fields that control imported HTML and base URL resolution.
3. Callback evidence proving server-side fetch.
4. Whether the response body is blind, semi-blind, or retrievable through stored media.
5. The lowest-risk internal reachability proof allowed by the scope.
6. The impact path: internal service discovery, image-compatible response exfiltration, or pivot into a more privileged server-side fetcher.
7. The regression cases: absolute image URL, relative image with attacker base URL, redirect, IPv6/IPv4 canonicalization, and multi-image validation parity.

## Operator notes

- Authenticated SSRF is still valuable when the permission is common, such as author/editor/contributor.
- Widget validation and preview APIs are often less protected than publish paths because teams treat them as temporary drafts.
- Image pipelines can hide response exfiltration behind normal media-library behavior. Always look for returned IDs and rewritten URLs, not just immediate response bodies.
- The safest proof is a controlled image callback plus stored-media byte comparison. Escalate beyond that only when the engagement explicitly allows it.
