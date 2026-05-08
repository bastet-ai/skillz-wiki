# Protocol, client, render, and resource-boundary batch

**Signal:** The **2026-05-08 20:15 UTC** advisory scan added protocol/client boundary issues across registry credential matching, unbounded cloud-metadata reads, HTTP start-line injection, ExifTool stdin argument injection, Jupyter token-theft XSS, Incus snapshot panic, and Apache Thrift traversal/splitting/resource/TLS validation failures.

## Advisory cluster

- **CycloneDX cdxgen registry credential forwarding** — [GHSA-qhh4-458h-xwh2](https://github.com/advisories/GHSA-qhh4-458h-xwh2): `@cyclonedx/cdxgen >= 9.9.5,<12.3.3` could forward Docker registry credentials to a different registry because of substring auth matching.
- **OpenTelemetry Azure resource detector unbounded HTTP read** — [GHSA-vc24-j8c5-2vw4](https://github.com/advisories/GHSA-vc24-j8c5-2vw4): `OpenTelemetry.Resources.Azure <= 1.15.0-beta.1` read unbounded HTTP response bodies.
- **Netty start-line injection** — [GHSA-v8h7-rr48-vmmv](https://github.com/advisories/GHSA-v8h7-rr48-vmmv): `netty-codec-http <= 4.1.132.Final` and `4.2.0.Alpha1..4.2.12.Final` could allow HTTP request smuggling / RTSP injection through `DefaultHttpRequest.setUri()`.
- **Gotenberg ExifTool stdin argument injection** — [GHSA-q7r4-hc83-hf2q](https://github.com/advisories/GHSA-q7r4-hc83-hf2q): `github.com/gotenberg/gotenberg/v8 <= 8.30.1` had a metadata newline bypass of earlier key sanitization.
- **Incus snapshot bounds-check panic** — [GHSA-4m88-wxj4-9qj6](https://github.com/advisories/GHSA-4m88-wxj4-9qj6): `github.com/lxc/incus/v6/cmd/incusd < 7.0.0` could panic via snapshot bounds handling.
- **Jupyter Notebook CommandLinker XSS token theft** — [GHSA-rch3-82jr-f9w9](https://github.com/advisories/GHSA-rch3-82jr-f9w9): `notebook >= 7.0.0,<=7.5.5`, `jupyterlab <=4.5.6`, and `@jupyter-notebook/help-extension >=7.0.0,<=7.5.5` exposed auth token theft through CommandLinker XSS.
- **Apache Thrift traversal/splitting/resource/TLS validation** — [GHSA-526f-jxpj-jmg2](https://github.com/advisories/GHSA-526f-jxpj-jmg2), [GHSA-2f9f-gq7v-9h6m](https://github.com/advisories/GHSA-2f9f-gq7v-9h6m), [GHSA-7pwc-h2j2-rjgj](https://github.com/advisories/GHSA-7pwc-h2j2-rjgj): Thrift packages `<=0.22.0` had path traversal, HTTP request/response splitting, excessive memory allocation, and host-mismatch certificate validation issues across affected ecosystems.

## Why this matters

The recurring failure is protocol boundary drift: a value is safe for display but not for a start line, safe as metadata but not as stdin to a CLI, safe as a registry prefix but not as an exact credential realm, or trusted after TLS without matching the intended host.

## Triage

1. Patch cdxgen, OpenTelemetry Azure detector, Netty, Gotenberg, Incus, Jupyter Notebook/JupyterLab, and Apache Thrift where present.
2. Review CI/build logs for Docker registry auth reuse across similarly named hosts.
3. Hunt for Netty `setUri()` call sites using unsanitized request targets, and conversion services that pass user metadata to ExifTool or other CLIs.
4. Check Jupyter access logs for unexpected CommandLinker/help-extension interactions followed by token use from unusual clients.
5. Exercise Thrift services with oversized length fields, path traversal segments, header splitting characters, and mismatched TLS certificates in test.

## Durable controls

- Match credentials to exact normalized registry origins, not substrings.
- Set response body, metadata, and parser allocation limits on every metadata service or protocol client.
- Validate HTTP request targets before serialization; reject CR/LF and authority-confusing forms.
- Pass CLI metadata through argv/structured files only after newline/control-character rejection.
- Require TLS hostname verification for every RPC/client library and cover it in integration tests.
- Treat notebook-rendered helper links as token-adjacent content: escape, sandbox, and keep tokens out of page-readable contexts.
