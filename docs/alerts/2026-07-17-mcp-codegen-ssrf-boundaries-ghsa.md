# MCP token, codegen, and map-import SSRF boundary checks

Sources: hourly offensive-security scan, 2026-07-17 GitHub Security Advisory updates. Primary entries: [GHSA-2v2f-mvfg-ph56](https://github.com/advisories/GHSA-2v2f-mvfg-ph56), [GHSA-45gf-fjxp-cjpq](https://github.com/advisories/GHSA-45gf-fjxp-cjpq), [GHSA-rjwr-m7qx-3fjr](https://github.com/advisories/GHSA-rjwr-m7qx-3fjr), and [GHSA-vqrw-qphh-p34v](https://github.com/advisories/GHSA-vqrw-qphh-p34v).

This batch is durable for operators because it hits three recurring assessment surfaces: HTTP-exposed MCP tools that confuse token presence with authorization context, spec-driven code generators that convert documentation fields into executable source, and import features that fetch attacker-supplied URLs from a privileged server position and reflect parsed content back to the caller.

!!! warning "Authorized validation only"
    Use lab MCP servers, fake Meta/ads tokens, owned callback hosts, disposable OpenAPI specs, and synthetic basemap/TileJSON services. Never replay real operator Meta tokens, call production ad accounts, query metadata services, scan internal networks, or execute generated code from an unreviewed customer spec.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-2v2f-mvfg-ph56](https://github.com/advisories/GHSA-2v2f-mvfg-ph56) / CVE-2026-54547 | `meta-ads-mcp` HTTP auth middleware | An arbitrary `X-Pipeboard-Token` value could satisfy the request gate while leaving no caller auth context, causing tool execution to fall back to the server operator's `META_ACCESS_TOKEN` | Test MCP HTTP transports for "some token header exists" checks that silently reuse process-level operator credentials. |
| [GHSA-45gf-fjxp-cjpq](https://github.com/advisories/GHSA-45gf-fjxp-cjpq) / CVE-2026-54549 | `meta-ads-mcp` `upload_ad_image` tool | `image_url` was fetched with redirects before real Meta API credential validation, allowing arbitrary server-side HTTP requests with only a dummy bearer value | Validate tool parameters that fetch media, documents, or images before authorization is fully bound to a principal. |
| [GHSA-rjwr-m7qx-3fjr](https://github.com/advisories/GHSA-rjwr-m7qx-3fjr) | `oapi-codegen` server URL generation | `servers[].description` from an OpenAPI document was emitted into generated Go comments without normalizing embedded newlines, allowing comment breakout and generated declarations | Treat OpenAPI specs from vendors, PRs, and bug reports as code-generation inputs, not passive documentation. |
| [GHSA-vqrw-qphh-p34v](https://github.com/advisories/GHSA-vqrw-qphh-p34v) / CVE-2026-54546 | TAK-PS-Stats CloudTAK basemap import | Authenticated `PUT /api/basemap` accepted a URL, fetched it server-side, parsed it as basemap metadata, and reflected fields such as name, attribution, tile URL, and zooms to the caller without IP-classification guards | Test map/feed/import features as full-read SSRF surfaces where parsed remote content is echoed back into an API response. |

## Replayable validation boundaries

### MCP token-context and pre-auth fetch checks

1. Deploy the MCP server only in a lab with fake environment tokens and a fake upstream ads API or recording proxy.
2. Compare request variants: no token headers, a normal bearer token, an arbitrary `X-Pipeboard-Token`, and a bearer value that is syntactically present but not valid upstream.
3. For credential-context bypass, call a harmless read-only canary tool and prove whether the process-level fake operator token is used when the caller did not authenticate as that operator.
4. For pre-auth SSRF, point `image_url` at an owned callback and then at a local synthetic HTTP service. Capture only method, path, and a marker response; do not target cloud metadata or internal production hosts.
5. Negative controls should include fixed middleware that binds every request to an authenticated caller before any tool code runs and URL fetch guards that classify the final post-redirect destination.

Report this as **HTTP MCP request header -> missing caller context -> process credential reuse**, or **tool media URL -> pre-auth server fetch -> owned callback reached before upstream credential validation**.

### OpenAPI code-generation injection checks

1. Use a disposable repository and a minimal OpenAPI spec with a `servers[].description` marker containing newline/comment-boundary canaries.
2. Run the generator in a locked-down workspace and inspect the generated diff before compiling or importing it.
3. Positive evidence is a generated Go file where spec-controlled description text escapes the intended comment and appears as code or declarations.
4. Keep canaries inert: marker variables or comments only. Do not use `init()` functions, shell execution, network clients, credential readers, or build-system hooks.
5. Negative controls should show newline normalization, safe quoting, or generator versions that render the marker as data.

Report this as **untrusted OpenAPI description -> generated Go source -> comment breakout/code injection before review**. Include the exact spec field, generated file path, sanitized diff, and fixed-generator output.

### Basemap import full-read SSRF checks

1. Confirm the target import route and authentication role in a lab or approved customer environment. Use a disposable low-privileged user if the product allows multiple roles.
2. Serve owned TileJSON-like responses from an internet callback and from a synthetic local service in the lab network. Include a harmless marker in fields that the endpoint reflects.
3. Submit basemap imports for allowed public URLs, disallowed internal-address canaries, redirect-to-internal canaries, and malformed hosts that exercise the parser.
4. Positive evidence is the route fetching the URL from the server and returning marker content in the API response. Stop at synthetic markers; do not read real internal pages, credentials, metadata, or service banners.
5. Negative controls should include IP-range classification on the final destination, redirect revalidation, scheme allowlists, size/content-type limits, and role checks before fetch.

Report this as **import URL -> server-side fetch -> parsed remote content reflected to caller**. Include URL decision tables, callback logs, response fields, and fixed-control behavior.

## Operator checklist

- [ ] Did authentication bind a caller identity before any MCP tool used process credentials or fetched remote content?
- [ ] Were all callbacks owned and free of metadata/internal probing?
- [ ] Was generated source inspected as a diff rather than executed directly?
- [ ] Did the SSRF proof show final-destination handling after redirects and parser normalization?
- [ ] Are tokens, ad-account IDs, internal hostnames, generated payloads, and customer topology redacted?
