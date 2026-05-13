# Render, MCP, command, and HTTP-boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because small helper features — content negotiation, cookie helpers, metadata tag names, and MCP HTTP endpoints — can quietly cross into browser script execution, HTTP response splitting, shell argument injection, or privileged tool invocation.

## Advisories covered

- **Fiber AutoFormat XSS** — [GHSA-qjv7-627w-8qjv](https://github.com/advisories/GHSA-qjv7-627w-8qjv): content negotiation/AutoFormat could emit scriptable output. Fixed in `fiber/v2 2.52.13` and `fiber/v3 3.2.0`.
- **Microdot response splitting** — [GHSA-7wc8-wvc4-m498](https://github.com/advisories/GHSA-7wc8-wvc4-m498): `Response.set_cookie()` accepted values that could split HTTP responses. Fixed in `2.6.1`.
- **exiftool-vendored argument injection** — [GHSA-cw26-7653-2rp5](https://github.com/advisories/GHSA-cw26-7653-2rp5): newline characters in tag names reached ExifTool arguments. Fixed in `35.19.0`.
- **Network-AI unauthenticated MCP HTTP endpoint** — [GHSA-fj4g-2p96-q6m3](https://github.com/advisories/GHSA-fj4g-2p96-q6m3): missing auth allowed unauthenticated privileged tool calls. Fixed in `5.1.3`.

## Operator triage

1. Patch public Fiber and Microdot services that reflect negotiated output or set attacker-influenced cookies.
2. Search logs for response-splitting probes: `%0d%0a`, raw CR/LF, duplicate headers, and injected `Set-Cookie`/`Location` headers.
3. Patch `exiftool-vendored`; review upload pipelines for attacker-controlled tag names, newline-delimited arguments, and ExifTool invocation logs.
4. Treat unauthenticated MCP HTTP endpoints as exposed admin planes. Disable them or bind to loopback until auth, origin, and network policy are verified.

## Durable controls

- Content negotiation must preserve output context: reflected data needs the encoder for the selected media type, not a generic serializer.
- Cookie/header helper APIs should reject CTLs, CR/LF, and invalid delimiters before constructing response headers.
- CLI wrappers must pass structured arguments with strict allowlists; metadata keys are not safe flag or argument names.
- MCP servers need explicit authentication, origin policy, audit logging, and least-privilege tool scopes even on “local” HTTP transports.
