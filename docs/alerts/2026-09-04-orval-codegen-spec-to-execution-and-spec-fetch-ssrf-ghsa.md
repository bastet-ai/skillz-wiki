# Orval codegen: OpenAPI-spec-to-execution trust and generation-time SSRF boundaries (GHSA)

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (Orval cluster, 12 advisories). Durable because Orval is a widely used OpenAPI → client/SDK code generator, and this cluster shows the **spec file is an executable trust boundary**: unescaped spec values become template/eval code at *import* and *generation* time, and the generator's own spec fetch is a remote/local file-inclusion SSRF surface.

Primary entries: [GHSA-fg9p-mrxr-hvq7](https://github.com/advisories/GHSA-fg9p-mrxr-hvq7) (RCE via OpenAPI path → unescaped request-URL template), [GHSA-88f2-fpv8-89q2](https://github.com/advisories/GHSA-88f2-fpv8-89q2) (RCE via `servers[].url` → unescaped request-URL template), [GHSA-cxq5-97v7-87j8](https://github.com/advisories/GHSA-cxq5-97v7-87j8) (generation-time SSRF + remote/local file inclusion), plus the import-time RCE cluster [GHSA-w727-8j6c-2rj4](https://github.com/advisories/GHSA-w727-8j6c-2rj4), [GHSA-2h9g-j24r-h63g](https://github.com/advisories/GHSA-2h9g-j24r-h63g), [GHSA-8j6p-r8jg-mxqh](https://github.com/advisories/GHSA-8j6p-r8jg-mxqh), [GHSA-2w86-xfrc-g85r](https://github.com/advisories/GHSA-2w86-xfrc-g85r), [GHSA-3575-w9fc-c2j6](https://github.com/advisories/GHSA-3575-w9fc-c2j6), [GHSA-653q-5476-x79g](https://github.com/advisories/GHSA-653q-5476-x79g), [GHSA-6437-gxhq-pqv8](https://github.com/advisories/GHSA-6437-gxhq-pqv8), [GHSA-p4cg-3328-rvfg](https://github.com/advisories/GHSA-p4cg-3328-rvfg), and [GHSA-6mr6-jvcr-2f25](https://github.com/advisories/GHSA-6mr6-jvcr-2f25) (schema default / property-name → zod module-level and computed-property-key RCE).

!!! warning "Authorized validation only"
    Keep proofs to a disposable Orval generation sandbox with a synthetic OpenAPI spec and a mocked/local spec server. Use inert template markers and denied `eval`/module-require/file sinks. Do not load untrusted spec code on a shared build host, do not fetch internal or cloud-metadata URLs, and do not read real repository files through the file-inclusion path.

## Why a code generator is an attacker surface

Orval turns an OpenAPI document into TypeScript/JavaScript client and SDK code. The cluster shows two distinct trust breaks:

1. **Spec values escape the template and reach JS `eval`/module scope at generation/import time.** A spec `path`, `servers[].url`, schema `default`, array-item `default`, header-parameter `default`, or even a **property name** / **enum value** / **query-parameter name** is interpolated into generated code in a position where an unescaped `</script>`-style or backtick/bracket payload becomes executable — either at code-generation (write) time or when the *generated module* is later `import`ed. The "import-time RCE" set (`GHSA-w727-8j6c-2rj4`, `GHSA-2h9g-j24r-h63g`, `GHSA-8j6p-r8jg-mxqh`, `GHSA-p4cg-3328-rvfg`, `GHSA-3575-w9fc-c2j6`) specifically lands in **zod schema module-level** code: a default value that is a JS expression executes when the generated module is evaluated.
2. **The generator's spec fetch is an SSRF/file-inclusion boundary.** `GHSA-cxq5-97v7-87j8` lets the OpenAPI source (a `url` the generator downloads) reach remote or local files without the expected host/protocol/`file://` filtering.

The reusable operator lesson: **a "schema/config file" that a codegen tool reads and interpolates into emitted source is an executable input.** Treat every generator, codegen, and OpenAPI toolchain as parsing untrusted, code-producing input.

## Boundary map

| Spec field | Emitted position | Defect | Reusable check |
| --- | --- | --- | --- |
| `paths` keys / `servers[].url` | request-URL template string | unescaped into template/eval | Feed a path or server URL containing a template-break payload; confirm it reaches the emitted URL string as data vs. code. |
| schema `default` | zod `z.literal()/z.default(...)` module code | default treated as JS expression | Set a `default` to an inert marker expression; confirm it executes at module import. |
| array-item `default`, header/query parameter `default` | generated schema code | same module-scope eval | Repeat per field class; record which field classes reach module scope. |
| schema **property name**, **enum value**, **query-parameter name** | computed-property-key position | name/enum interpolated as a key/expression | Feed a name/enum with a payload; confirm it becomes a computed key rather than a quoted string. |
| OpenAPI source `url` | generator's spec fetch | SSRF + `file://`/local include | Point the source at a local marker file and an owned no-content peer; record the fetch target and returned bytes. |

## Replayable validation boundaries

### Spec-value-to-template (request-URL) escape

1. In a disposable Orval sandbox, author a synthetic OpenAPI spec whose `paths` key (or `servers[].url`) contains a template-break canary — for example a value that would close a backtick/`${}` and insert a marker call, or a value that is obviously code rather than data.
2. Run generation and capture the **emitted** request-URL template. Positive is the canary appearing in the source as executable position (unescaped), not as a quoted literal.
3. Stop at the emitted-code differential. Do not actually run the generated client against a live endpoint to trigger execution.

### Import-time RCE via zod schema module scope

1. Build a synthetic spec with a schema `default` (then array-item, header-parameter, and query-parameter defaults, then a property name and an enum value) set to an inert marker expression that would create a canary file or log a nonce *if evaluated*.
2. Generate the client and **import the generated module** in an isolated node process that denies real file writes and network.
3. A positive is the canary side effect occurring at `import` time (module-scope eval). Record, per field class, whether the value reached module scope. Use a denied file/network sink so the proof is "expression evaluated at import," not "file written."
4. Negative control: the same spec on the fixed Orval version, where defaults/names are quoted/emitted as data.

### Generation-time spec-fetch SSRF + file inclusion

1. Point the OpenAPI source `url` at three targets in sequence: a **local marker file** (`file:///tmp/orval-canary`), an **owned no-content HTTP peer**, and (only in cloud scope, only if explicitly authorized) a metadata address.
2. Record, per target, whether the generator dials it, what protocol/authority it uses, and what bytes reach the parser. A positive is the generator fetching a local file or an unfiltered remote host.
3. Keep proof to the fetch-target decision table and the returned canary bytes; never reach cloud metadata, internal services, or real repository files beyond the marker.

## Durable operator value

1. **Codegen tools are code-producing parsers.** Any tool that reads a spec/config and emits source is an injection surface: the input is data to *you* but code to the *emitter*. Audit every codegen (OpenAPI, protobuf, GraphQL, wiremock, mock servers) for unescaped interpolation into emitted source.
2. **Module-scope eval is the high-impact leg.** A value that lands in generated *module-level* code runs at import, which is often earlier and more trust-granted than a function body. Prioritize `default` values, computed keys, and names over ordinary request fields.
3. **"Default" and "name" fields are under-audited injection channels.** Security reviews focus on request bodies; the Orval cluster shows that schema defaults and property names carry the same payload. Extend injection testing to *generator input metadata*, not just runtime request data.
4. **The spec-fetch is a separate SSRF boundary.** Codegen that downloads a spec has its own SSRF/file-inclusion surface independent of the runtime client. Test the fetch path (host/protocol/`file://` filtering) separately from the emitted-code path.
5. **Proof is emitted-code + import-time side effect, not live exploitation.** The durable artifact is the emitted-source differential and the import-time canary — safe to report, safe to replay, and decisive.

## Safety

- **Isolated generation sandbox.** Deny real file writes, process spawn, and network from the node process that imports generated code.
- **Synthetic specs only.** No production OpenAPI documents, no real endpoints, no untrusted third-party specs.
- **Spec fetch stops at the canary decision table.** No internal-service, metadata, or real-repository-file access.
- **Never load untrusted generated code on a shared CI host.** If validating a real pipeline, run in an ephemeral, egress-blocked container and treat the generated artifacts as untrusted.

---

*Source: hourly offensive-security scan, 2026-09-04. All 12 Orval advisories tracked in the [source index](../notes/source-index.md).*

## October 10 follow-up: openapi-typescript-codegen — same spec-fields-to-emitted-code invariant, single-quoted template this time (CVE-2026-108551 / [GHSA-3pr5-x7xf-mg4g](https://github.com/advisories/GHSA-3pr5-x7xf-mg4g), critical, ≤0.31.0)

Second independent OpenAPI→TypeScript codegen with the identical defect: attacker-controlled values in the OpenAPI document are interpolated **unescaped into single-quoted string literals** in the emitted client; a single quote in a **path key, parameter name, `servers[0].url`, or `info.version`** closes the literal and injects arbitrary JavaScript that runs when the generated client is imported or a service method is called. Same field inventory this page already prescribes (names, keys, URLs, version strings — generator *metadata*, not request data); only the quoting style differs (backticks/`${}` here → plain `'...'` there).

Operator takeaways: (1) the recurrence across two unrelated generators proves the pattern is *idiomatic* codegen practice (string-interpolate the spec), not one vendor's mistake — every OpenAPI/AsyncAPI/gRPC client or mock generator is a candidate; run this page's emitted-source differential against the target generator with a quote-class canary for **each** quote style it emits (`'`, `"`, `` ` ``), because a generator patched for template-literal breaks frequently still splices the same field into single quotes elsewhere. (2) The `servers[0].url` and `info.version` legs show version/metadata strings — fields nobody treats as input — reach executable position; include them in every synthetic spec. (3) Spec-consumption trust inversion: on any engagement where a team generates clients from third-party or vendored OpenAPI docs (partner APIs, internal spec registries, marketplace specs), the spec is an upstream supply-chain input — the generated artifact is untrusted code and the canary stop-at-emitted-differential rule stands.
