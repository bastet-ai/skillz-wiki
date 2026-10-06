---
title: OpenAPI and schema code-generation boundaries from July 24-30 GHSA updates
---

# OpenAPI and schema code-generation boundaries from July 24-30 GHSA updates

A July 24 GitHub advisory wave exposes two reusable review surfaces: OpenAPI metadata crossing into generator network, filesystem, shell, source-code, and downstream plugin-manifest sinks; and typed serialization control nodes resolving attacker-selected values from a general object table. The value is not package-version alerting. It is a set of bounded tests for developer tools and server-side deserializers that consume attacker-influenced structured input.

Sources:

- [GHSA-3hrf-2gc2-mx32 / CVE-2026-59860: Kiota C# XML doc-comment newline breakout](https://github.com/advisories/GHSA-3hrf-2gc2-mx32)
- [GHSA-7f3j-j7jj-r3vr / CVE-2026-59862: Kiota Python enum-description code generation injection](https://github.com/advisories/GHSA-7f3j-j7jj-r3vr)
- [GHSA-xg2h-5xr2-29jw / CVE-2026-59861: Kiota Ruby literal interpolation injection](https://github.com/advisories/GHSA-xg2h-5xr2-29jw)
- [GHSA-jqwh-526h-c92j / CVE-2026-59859: Kiota PHP literal interpolation injection](https://github.com/advisories/GHSA-jqwh-526h-c92j)
- [GHSA-hq9q-27g5-qwpj / CVE-2026-59865: Kiota description-supplied dependency install command](https://github.com/advisories/GHSA-hq9q-27g5-qwpj)
- [GHSA-4vv7-jj25-4gh6 / CVE-2026-59866: Kiota class/namespace file-path injection](https://github.com/advisories/GHSA-4vv7-jj25-4gh6)
- [GHSA-4rj6-vrwv-wr8m / CVE-2026-59863: Kiota workspace output-path escape](https://github.com/advisories/GHSA-4rj6-vrwv-wr8m)
- [GHSA-rg4h-fpcp-2qm8 / CVE-2026-59867: Kiota external `$ref` SSRF and file inclusion](https://github.com/advisories/GHSA-rg4h-fpcp-2qm8)
- [GHSA-4jwf-m4wg-8p66: Kiota AI plugin static-template path injection](https://github.com/advisories/GHSA-4jwf-m4wg-8p66)
- [GHSA-p5rm-jg5c-8c77: encoded Kiota static-template traversal bypasses](https://github.com/advisories/GHSA-p5rm-jg5c-8c77)
- [GHSA-mv8w-475r-vwqw / CVE-2026-59940: Seroval Promise resolver type confusion](https://github.com/advisories/GHSA-mv8w-475r-vwqw)

The same publication wave included Valibot and LZ4 crash paths, an AWS CLI local-permissions issue, ONNX and ImageMagick memory-safety records, and a SvelteKit remote-form resource-exhaustion issue. Those are not expanded because this page focuses on exact, replayable source-to-sink boundaries rather than availability-only or local-host findings.

!!! warning "Authorized validation only"
    Use disposable repositories, synthetic OpenAPI descriptions, temp output roots, owned HTTP callbacks, fake dependency commands, generated clients that never leave the lab, and inert Seroval plugins. Do not point generators at cloud metadata or production internal services, read workstation secrets, overwrite shell or CI configuration, execute downloaded packages, deploy tainted generated clients, or invoke real server tools during deserialization.

## Operator use

Use these checks when scope includes:

- SDK generation from partner, tenant, repository, marketplace, or remotely hosted OpenAPI descriptions;
- pull requests that can modify `.kiota/workspace.json`, API descriptions, lockfiles, generated-client inputs, or AI plugin metadata;
- CI jobs or IDE extensions that run `kiota generate`, `kiota info`, dependency installation, generated-code compilation, or generated tests;
- Microsoft 365 Copilot or Teams plugin packages generated from `x-ai-adaptive-card` or `x-ai-capabilities` extensions;
- applications or frameworks that call `seroval.fromJSON()` on browser-, tenant-, cache-, RPC-, or job-controlled JSON with plugins enabled.

## Build one provenance map

Do not test every string blindly. Map each attacker-reachable field to the phase and interpreter that consumes it:

| Input | Kiota or framework phase | Sensitive sink | Safe proof |
| --- | --- | --- | --- |
| OpenAPI `$ref` | description resolution | build-host HTTP request or local file read | owned callback and synthetic out-of-tree schema |
| `.kiota/workspace.json` `outputPath` | workspace regeneration | filesystem write outside repository | marker-only temp sibling directory |
| `x-ms-kiota-info` names | source layout and declarations | output path plus generated identifier/context | generated filename and non-executable marker text |
| `dependencyInstallCommand` | `kiota info` / IDE handoff | human- or IDE-triggered shell | fake command string plus dry-run argument capture |
| descriptions, defaults, wire names | language writer | comment or quoted-literal breakout | harmless declaration/counter in isolated generated source |
| `static_template.file` | plugin-manifest generation and AI-host load | out-of-package path/URI resolution | synthetic sibling card plus manifest-resolution trace |
| Seroval Promise control node | `fromJSON()` graph resolution | method invocation on plugin-produced value | inert object method that increments a local counter |

Preserve the input document hash, Kiota command and version, workspace root, generated file list, outbound callback record, emitted source/manifest snippet, and fixed-version result. The report should separate effects that happen **during generation** from those that require **building/importing generated code** or **loading a plugin package downstream**.

## Kiota external-reference network and file boundaries

Affected Kiota versions before 1.32.5 could resolve remote and local external `$ref` values without an explicit allowlist. This is valuable as a generator-side SSRF/LFI check, but the proof should stop at schema inclusion.

### Bounded fixture

1. Create a disposable workspace with one root OpenAPI document.
2. Host a second synthetic schema at an owned callback origin. Give it a unique, harmless property such as `REMOTE_SCHEMA_CANARY`.
3. Place another synthetic schema in a temp sibling directory outside the workspace. Give it `SIBLING_SCHEMA_CANARY`; do not use a system or user file.
4. Reference each schema separately through `$ref`, including one nested reference to determine whether resolution is transitive.
5. Run the same Kiota generation command used by the target workflow. Capture the callback and search only the generated temp output for the canary property.
6. Repeat with Kiota 1.32.5 or later without `--allowed-external-origins`, then with a narrowly scoped owned origin/path allowed.

A positive result is **attacker-influenced OpenAPI document -> generator resolves an unapproved URL/path -> canary schema appears in generated output**. It is SSRF or local inclusion, not code execution. Never substitute metadata endpoints, internal admin APIs, credentials, or unrelated local files.

## Kiota workspace and metadata file-write boundaries

There are two distinct sources and they should produce separate findings:

- repository-controlled `.kiota/workspace.json` `outputPath`; and
- description-controlled `x-ms-kiota-info.clientClassName` or `clientNamespaceName` used in output layout.

### Temp-root matrix

1. Put the repository under `TEMP/repo` and create `TEMP/outside` with a marker indicating that the directory is disposable.
2. For the workspace case, set one consumer's `outputPath` to a relative sibling escape and, in a separate run, an absolute path under `TEMP/outside`.
3. For the metadata case, omit `-c/--class-name` so the zero-config `x-ms-kiota-info` path is reached. Use class and namespace values containing only a path-shaped canary aimed at `TEMP/outside`.
4. Run generation under a recorder that inventories created paths. Do not choose startup files, package-manager hooks, web roots, CI configuration, or executable search paths.
5. Confirm whether generated marker source appears outside `TEMP/repo`; then repeat with 1.32.5 or later.

Report **repository config to out-of-workspace generation** separately from **OpenAPI metadata to filename/namespace generation**. The class-name advisory explicitly notes that malformed names reused at several sites break compilation; do not overstate the demonstrated file-write/build-corruption primitive as clean RCE.

## Dependency-command trust handoff

In affected Kiota versions, `x-ms-kiota-info.languagesInformation.<language>.dependencyInstallCommand` could replace Kiota's normal recommendation in `kiota info` and its JSON output. Reachability depends on a developer or IDE action that executes the recommendation.

1. Use a description whose command is an inert marker such as `printf kiota-canary > TEMP/command-seen`; do not download or install anything.
2. Run both human-readable `kiota info` and `kiota info --json` and capture the exact field provenance.
3. If an IDE extension is in scope, instrument its process-spawn boundary or replace the shell runner with an argument recorder. Do not allow the marker command to reach a real shell unless explicitly authorized in the disposable lab.
4. Show whether the description-controlled string is merely displayed, offered behind confirmation, or executed by one click/automation.
5. Repeat on 1.32.5 or later, where the description-supplied command should no longer be surfaced.

The chain is **untrusted API description -> trusted tool recommendation/JSON -> human or IDE install action -> command execution**. State the required action precisely.

## Generated-language context checks

The C#, Python, Ruby, and PHP records are a compact code-generator sink taxonomy:

| Target | Attacker-shaped source | Dangerous context | Harmless validation |
| --- | --- | --- | --- |
| C# | description or external-doc text | newline exits `///` XML comment | emit a benign constant; compile only in a sandbox |
| Python | `x-ms-enum.values[].description` | newline exits generated comment | import increments an in-memory marker counter |
| Ruby | defaults or property wire names | `#{...}`, `#$...`, or `#@...` interpolation in double quotes | interpolation returns a fixed marker string |
| PHP | descriptions, defaults, or property names | `${...}`, `$var`, or `{$...}` interpolation in double quotes | expression returns a fixed marker string |

Use one generated client per language and a harmless marker—never a shell, network call, environment read, or persistence action. Capture the exact input field, emitted source context, syntax/compiler result, and whether the marker executes at generation, compile, import, construction, serialization, or request time. Fixed baselines differ: C# at 1.32.3, Python/Ruby at 1.32.0, PHP at 1.32.4; use 1.34.0 or later for the complete cluster including later plugin-path fixes.

## AI plugin static-template confinement

`static_template.file` is not opened on the Kiota build host in the reported chain. Kiota emits it into a generated Copilot/Teams plugin manifest, and a downstream AI host may later resolve it relative to the plugin package.

1. Generate an API plugin from a synthetic description using both `x-ai-adaptive-card.file` and `x-ai-capabilities.response_semantics.static_template.file` paths.
2. Test literal parent traversal, absolute/rooted forms, URI forms, percent-encoded separators/dots, double encoding, encoded NUL/control characters, and Unicode full-width dot forms.
3. Inspect the generated manifest first. Then use only a disposable local package resolver or test host containing `package/adaptiveCards/card.json` and `sibling/card-canary.json`.
4. Record the raw field, every decoding/normalization pass, manifest value, resolved final path, and whether it remains under the package root.
5. Compare 1.32.4, 1.32.5, and 1.34.0 where feasible: the advisory sequence documents an initial confinement fix followed by percent-encoding and residual canonicalization fixes.

A valid report proves **description field -> generated manifest -> downstream normalization -> synthetic out-of-package canary selected**. Do not claim build-host file read or production AI-host disclosure unless that separate sink is actually demonstrated.

## Seroval control-node type-confusion validation

The Seroval issue is narrower than generic “JSON causes RCE.” Preconditions are:

- the application accepts attacker-controlled Seroval JSON;
- it calls `seroval.fromJSON()`;
- plugins are enabled; and
- a registered plugin can deserialize a callable, privileged, or method-bearing wrapper that the confused Promise resolver can invoke.

### Inert harness

1. Pin `seroval@1.5.2` in a local Node harness and register one test-only plugin that returns an object with resolver-shaped method names. Each method should only increment a counter and append a marker to an in-memory event list.
2. Serialize a legitimate Promise-containing graph and record the expected internal control-node/reference layout. This gives a format baseline without copying a weaponized payload.
3. Mutate only the reference target so a Promise control node points to the plugin-produced object in the general reference table.
4. Call `fromJSON()` and record whether deserialization itself invokes the marker method before application code intentionally uses the value.
5. Repeat with `seroval@1.5.3`; the expected negative control is rejection before the side effect.
6. For a downstream framework, prove the exact route or RPC body reaches this path and replace all real framework tools with inert wrappers. Package presence alone is insufficient.

Lead with **untrusted typed graph -> control-node/reference-table type confusion -> plugin-produced method invoked as a deserialization side effect**. Only call it RCE when the target application registers a concretely reachable execution-capable wrapper; otherwise report the unintended invocation primitive.

## Reporting notes

Include:

- attacker control over the repository, description, manifest field, or serialized graph;
- exact command/API and version;
- source field and all transformations;
- the phase where the side effect occurs;
- disposable path/callback/counter evidence;
- a patched negative control; and
- the extra user, IDE, compile, import, deployment, or plugin precondition.

Avoid collapsing the cluster into “malicious OpenAPI equals RCE.” External `$ref` stops at fetch/inclusion in the confirmed advisory; class-name injection provides out-of-root writes but malformed generated code may not compile; plugin template paths are realized downstream; and Seroval impact depends on registered plugins and framework reachability.

## July 26 follow-up: JSON Schema `customBasePath` to generated Python import

[GHSA-7x49-hhjc-29rg / CVE-2026-63720](https://github.com/advisories/GHSA-7x49-hhjc-29rg) reports that `datamodel-code-generator` before 0.70.0 accepts schema-controlled `customBasePath` values containing newlines and emits them into a Python `from ... import ...` statement. The [primary validation commit](https://github.com/koxudaxi/datamodel-code-generator/commit/545a96c5) adds a dotted-Python-identifier validator for scalar and nested-list values and tests both file generation and `generate_dynamic_models()`.

This is the same source-generation boundary as Kiota's language-writer findings, but with two distinct execution phases:

- CLI/file generation writes attacker-shaped Python that executes only if a later workflow imports or runs it;
- dynamic-model APIs may generate and execute the resulting module in the same application process.

### Inert generation/import differential

1. Use a disposable JSON Schema with one ordinary model and a unique `customBasePath` canary. Keep the injected line to a harmless module-level assignment such as `DMCG_CANARY = "<nonce>"`; do not use imports, calls, environment reads, shell syntax, or network access.
2. Run the exact CLI, library `generate()`, or dynamic-model API reached by the assessed workflow under a temporary output root.
3. Before importing anything, preserve the schema hash, generator version/options, emitted filename, and the generated `from` statement plus adjacent canary line.
4. For file-generation workflows, import the generated module only in a fresh disposable interpreter and read the inert variable. This separates **source emitted** from **generated source executed**.
5. For dynamic-model workflows, use an in-memory marker or instrument the module-execution boundary to establish whether execution occurs during the API call.
6. Repeat with valid scalar and list `customBasePath` controls, then with 0.70.0 or the linked validation commit. The unsafe fixture should fail before an output file exists or dynamic execution begins.

The useful proof is **attacker-controlled schema extension -> newline escapes generated import context -> inert statement appears -> only the actually reachable import/dynamic phase observes the marker**. Require evidence that the target accepts untrusted schemas and later imports or dynamically executes generated code; package presence or malformed generated text alone is not RCE.

## July 28 datamodel-code-generator source/fetch/file wave

A second `datamodel-code-generator` wave expands the `customBasePath` lesson into a full schema-ingestion matrix. Treat remote retrieval, local include resolution, source emission, and later import as different sinks.

Sources and reviewed fixed controls:

- generated Python contexts: [GHSA-j884-q54q-mmx3](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-j884-q54q-mmx3) (GraphQL Union-description CR breakout, fixed 0.60.1), [GHSA-wjv6-jcfj-mf9r](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-wjv6-jcfj-mf9r) (extras comment CR breakout, fixed 0.60.2), [GHSA-386q-5hp3-95m9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-386q-5hp3-95m9) (`default_factory`, fixed 0.60.2), [GHSA-8m8r-38jm-f355](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-8m8r-38jm-f355) (validator fields/mode, fixed 0.60.2), [GHSA-m34r-v34r-rf9q](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-m34r-v34r-rf9q) (`x-python-type`, fixed 0.60.2), and [GHSA-5578-w22f-pfx9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-5578-w22f-pfx9) (`x-python-import`/`customTypePath`, fixed 0.64.0);
- outbound fetches: [GHSA-rfr2-mq9m-x2qx](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-rfr2-mq9m-x2qx) (`--url`, fixed 0.61.0), [GHSA-954p-556p-r752](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-954p-556p-r752) (HTTP `$ref` fetched by default, fixed 0.61.0), [GHSA-r5vv-ff45-prp2](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-r5vv-ff45-prp2) (headers retained across cross-origin redirect, fixed 0.63.0), and [GHSA-vx7x-vcc2-c44g](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-vx7x-vcc2-c44g) (DNS validate/connect rebinding gap, fixed 0.63.0);
- local includes: [GHSA-442q-2j6p-642g](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-442q-2j6p-642g) (XSD `schemaLocation`, fixed 0.62.0) and [GHSA-8359-h9fx-j6v9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-8359-h9fx-j6v9) (JSON Schema `file://` and relative `$ref`, fixed 0.62.0).

### Source-context fixture

1. Run each input in a disposable repository with no credentials, network tokens, package hooks, or importable production modules. Preserve the generator version, input hash, options, output tree, and emitted source diff.
2. Use one inert assignment per source field. Test CR, LF, CRLF, quote, backslash, dotted-identifier, and list-element boundaries independently in descriptions, extras comments/validators, `default_factory`, `x-python-type`, `x-python-import`, and `customTypePath`.
3. First prove only that the marker escaped its expected comment, quoted value, type annotation, decorator, or import context. Syntax errors are useful negative evidence but are not execution.
4. If the real workflow imports generated models, do so only in a fresh sandbox and observe an in-memory variable or no-op counter. Never use process launch, environment reads, callbacks, persistence, or package imports as the marker.
5. Repeat at the specific fixed version. Because fixes landed across 0.60.1, 0.60.2, and 0.64.0, testing one intermediate release can leave sibling sinks reachable.

### Fetch, redirect, and local-reference fixtures

Use two owned loopback listeners: A serves the root schema and redirects; B serves a synthetic nested schema and records only path, origin, and presence of a fake header. Exercise `--url` and remote `$ref` separately across default behavior, explicit remote-reference denial, same-origin redirects, and cross-origin redirects. A positive redirect result is that B receives the fake header after A changes host, port, or scheme; never use a live credential.

For rebinding, use a fully owned DNS/test-resolver fixture whose first lookup maps to an owned global test listener and second lookup maps to loopback. Prove validation of one address followed by connection to the other owned canary. Never query metadata, RFC1918 services, or production localhost endpoints.

For file confinement, create `TEMP/repo/schema` and `TEMP/sibling/schema-canary` under one disposable parent. Test JSON Schema relative `$ref`, `file://`, and XSD `xs:include`/`xs:import` `schemaLocation` independently, including sibling-prefix and symlink controls. Run with explicit remote references disabled as a control. The positive result is **resolved local target leaves the input/base root and its synthetic type marker reaches generated output**. Do not read system files, home files, CI config, cloud credentials, or unrelated repositories.

Report narrow edges: **schema field to generated Python context**, **schema URL/reference to owned outbound fetch**, **trusted-host header to redirected origin**, **validated DNS answer to different connection address**, or **local include to out-of-root canary**. State whether generated source was merely emitted or actually imported by the assessed workflow.

## Style Dictionary token-path prototype boundary

[GHSA-vj5c-m527-mpff / CVE-2026-54639](https://github.com/style-dictionary/style-dictionary/security/advisories/GHSA-vj5c-m527-mpff) adds a generated-design-token variant. Style Dictionary `>=4.3.0,<5.4.4` could pass a token key such as `{__proto__.canary}` through `convertTokenData(..., { output: 'object' })`; the same conversion is reached indirectly by enabled Expand and transform lifecycle paths. The advisory confirms process-global `Object.prototype` pollution, but downstream impact still depends on a separate gadget.

Use a fresh Node process per row and synthetic token arrays only. Compare direct `convertTokenData`, Expand enabled/disabled, transform lifecycle, DTCG/legacy token shapes, `__proto__`, `constructor.prototype`, nested segments, and 5.4.4. Before and after each call, inspect a unique inert property on `{}`, the returned object's own keys/prototype, and one no-op sink object. Do not use authentication, process-spawn, filesystem, template-execution, or network gadgets.

Report **untrusted token path -> object conversion/transform -> process-global prototype gains synthetic marker** separately from any downstream effect. Require evidence that a server, collaborative build API, pull-request workflow, or plugin accepts attacker-controlled tokens; repository maintainers transforming only their own trusted tokens have a different boundary. Reset the process between tests so one polluted row cannot contaminate controls.

## July 29 swagger-typescript-api generation wave

Six reviewed advisories expand the same OpenAPI trust model to `swagger-typescript-api <=13.12.1`; all list 13.12.2 as the first patched version:

- [GHSA-w284-33mx-6g9v / CVE-2026-54666](https://github.com/advisories/GHSA-w284-33mx-6g9v): path keys reach generated JavaScript template literals;
- [GHSA-5f94-x226-ccpm / CVE-2026-54664](https://github.com/advisories/GHSA-5f94-x226-ccpm): enum strings reach generated TypeScript enum declarations;
- [GHSA-hqj5-cw9f-rx67 / CVE-2026-54662](https://github.com/advisories/GHSA-hqj5-cw9f-rx67): `servers[0].url` reaches the fetch client's class-body initializer;
- [GHSA-38c3-wv3c-v3xj / CVE-2026-54661](https://github.com/advisories/GHSA-38c3-wv3c-v3xj): the same server URL reaches the axios client constructor;
- [GHSA-x36r-4347-pm5x / CVE-2026-54663](https://github.com/advisories/GHSA-x36r-4347-pm5x): remote `$ref` traversal causes generation-time outbound fetches; and
- [GHSA-h754-fxp7-88wx / CVE-2026-54660](https://github.com/advisories/GHSA-h754-fxp7-88wx): generator authorization headers follow cross-origin `$ref` requests.

Do not collapse these into one generic code-execution claim. They expose four different phases:

| Spec-controlled field | Observed boundary | Earliest relevant phase | Inert proof |
| --- | --- | --- | --- |
| `paths` key | unescaped template-literal interpolation | affected generated method call | fixed string expression or no-op counter |
| schema enum value | quoted enum/declaration breakout | generated-module import | harmless module-level marker |
| `servers[0].url`, fetch client | class-body field breakout | generated-module import | harmless static marker |
| `servers[0].url`, axios client | constructor object-literal breakout | client construction | constructor-local no-op counter |
| external `$ref` | unrestricted recursive HTTP resolution | generation | owned callback serving a synthetic schema |
| external `$ref` plus authorization option | credential forwarded to another origin | generation | fake token observed by a second owned listener |

### Generated-source phase matrix

1. Pin 13.12.1 in a disposable Node project with no credentials, lifecycle hooks, production modules, or unrestricted egress. Generate one client per field and HTTP client type.
2. Keep markers non-executable at first: inspect whether quote, backslash, backtick, `${...}`, CR, LF, and Unicode line-separator fixtures escape the expected string, enum, path, or class context.
3. Preserve the source spec hash, command/options, generated tree, exact emitted snippet, and parser/type-check result. A syntactically invalid output proves unsafe emission or build corruption, not execution.
4. If the assessed workflow imports generated modules, construct clients, or calls generated methods, test those phases separately in fresh processes. Use only an in-memory variable or instrumented no-op counter; do not read files, environment variables, spawn processes, or make callbacks.
5. Repeat the complete matrix on 13.12.2. Include both default/modular output and fetch/axios modes where the target uses them.

The useful report states **which spec field escaped which generated-code context and exactly when the harmless marker became observable**. Import-time enum or fetch-client effects are different from axios construction and path-method invocation.

### External-reference and credential-origin matrix

Use two owned loopback listeners. Listener A serves the root OpenAPI document; listener B serves one nested schema and records method, path, and only whether an exact fake authorization marker is present.

1. Compare a local-only control, same-origin `$ref`, direct cross-origin `$ref`, same-origin redirect, and redirect to B.
2. Run once without authorization and once with a unique fake value such as `Bearer STA_CANARY_ONLY`; never place a live PAT, API key, cookie, or CI credential in the harness.
3. Add one nested `$ref` from B back to an already visited URL and another to a second B path. Record recursion, de-duplication, redirect behavior, and every destination selected by the generator.
4. For network-policy testing, use only owned listeners and a controlled resolver. Do not request metadata, localhost services you do not own, RFC1918 applications, or corporate/VPN endpoints.
5. Repeat on 13.12.2. Confirm both that unapproved destinations are not contacted and that authorization is not forwarded when scheme, host, or port changes.

Report separate edges: **spec reference -> generator-side fetch** and **root-spec credential -> cross-origin reference request**. A callback proves SSRF reachability, not response disclosure; a fake header at B proves origin-scope failure without exposing a real secret.

## July 30 AWS Amplify component-schema follow-up

[GHSA-hf3j-86p7-mfw8 / CVE-2025-4318](https://github.com/advisories/GHSA-hf3j-86p7-mfw8) adds a UI-builder variant of generated-source injection. AWS Amplify Studio and the Amplify CLI consume component schemas and `@aws-amplify/codegen-ui-react` turns binding properties into React/JSX expressions. The advisory says an authenticated user who can create or modify components can reach arbitrary JavaScript during component rendering and build processing.

Primary fix records make the source fields more precise:

- [PR 1174](https://github.com/aws-amplify/amplify-codegen-ui/pull/1174) added escaping for property values used by `buildBindingExpression()` and shipped in 2.20.3; and
- [PR 1196](https://github.com/aws-amplify/amplify-codegen-ui/pull/1196) identifies residual `bindingEvent`, `field`, default-binding, and collection-binding paths and applies the same validation in 2.20.4.

Preserve the version nuance: GitHub's package metadata labels 2.20.3 as the first patched version, while the advisory narrative calls that fix partial and directs users to 2.20.4 for the additional paths. Use 2.20.4 or later as the complete negative control rather than treating one safe property-binding row on 2.20.3 as proof that every sink is closed.

### Schema-field to execution-phase matrix

| Component-schema source | Generator sink | Earliest phase to test | Bounded evidence |
| --- | --- | --- | --- |
| binding `property` value | expression builder | generated-source parse/import or preview render | harmless literal/counter escapes its intended expression position |
| binding `field` | standard, default, and collection binding builders | generated-source parse/import or preview render | field marker changes generated AST shape without invoking a privileged API |
| event `bindingEvent` | identifier construction in the workflow event path | generated handler import or event dispatch | synthetic event increments a recorder-only counter |
| collection child binding | recursive component rendering | collection preview/build | one synthetic child marker reaches the generated child expression |

### Inert Studio/CLI harness

1. Use a disposable Amplify project with no cloud credentials, deployment role, package-publishing token, lifecycle hooks, browser session, or unrestricted egress. Pin `@aws-amplify/codegen-ui-react` 2.20.2, 2.20.3, and 2.20.4 in separate clean workspaces.
2. Start from a valid exported component schema. Create one fixture per source row: ordinary property binding, default-valued binding, collection child binding, and workflow event binding. Vary quote, backslash, line separator, reserved-word, and expression-boundary characters independently; do not copy an execution payload from a public proof of concept.
3. Keep the first marker structural. Generate the component and preserve input hash, CLI/API path, package version, emitted file hash, AST diff, and parser/type-check result. Malformed or attacker-shaped generated syntax proves unsafe emission, not JavaScript execution.
4. Where the assessed workflow actually renders previews, imports generated modules, builds the application, or dispatches generated event handlers, exercise those phases separately in a fresh sandbox. Replace effects with an in-memory variable or recorder-only function; never read environment variables, access files, make network requests, spawn a process, or deploy the component.
5. For the Studio path, prove the exact authorization precondition with two disposable users: one who can create/modify a test component and one who cannot. Use only a synthetic app/component and capture component ownership plus API decision; do not modify another tenant's component.
6. Repeat every row on 2.20.3 and 2.20.4. Expect the original property-value row to be useful for demonstrating the partial fix, while the residual event/field/default/collection rows require the complete 2.20.4 control.

Report the narrow chain: **authenticated component-schema control -> exact binding field -> generated JSX/identifier context -> generated source parses -> only the reachable preview/import/build/event phase observes the inert marker**. Do not collapse `create-component` authorization, unsafe source generation, preview rendering, build-time execution, browser execution, or deployment into one “Amplify RCE” claim; each is a separate edge and some workflows stop before later phases.

## October 6 follow-up: comment-delimiter reformation in Java/PHP generators + unvalidated `oauth_card_path` in AI plugin manifests (2 GHSAs)

[GHSA-rm89-rhwj-9j92 / CVE-2026-105796](https://github.com/advisories/GHSA-rm89-rhwj-9j92) (Kiota ≥0.5.0 <1.35.0, 8.8) and [GHSA-6gw6-rv2g-25mg / CVE-2026-105795](https://github.com/advisories/GHSA-6gw6-rv2g-25mg) (<1.35.0, low but architecturally new) close two more edges of the generated-source trust boundary this page already maps.

- **Strip-based sanitizers reform what they delete.** The Java/PHP doc-comment sanitizer *removes* `*/` and other terminators from OpenAPI description text; overlapping characters (`*` /) or a later normalization pass (the Java path removes non-ASCII characters *after* terminator removal, so `*/` can form from what looked like two unrelated characters, e.g. a non-ASCII char normalized away leaving `*` adjacent to `/`) reconstitute a live block-comment terminator. The attacker's text then escapes the doc comment and lands as emitted source in the generated client, which executes when a pipeline compiles/loads it. Note the backport trap the advisory itself calls out: the "security-backport" 1.29.1 is *still vulnerable* — security-release labels are not fix evidence; only 1.35.0 neutralizes (replaces delimiters instead of deleting them, and re-orders normalization before delimiter handling).
  - Durable audit rule: **for every "we delete the dangerous characters" sanitizer in a generator/templating layer, test reformation, not just survival** — feed overlapping prefixes (`*//`), characters that later passes remove or fold, and Unicode that normalizes into a delimiter component. This is the same genealogy as the Oct 3 AVideo doubly-encoded-entity check (strip-before-decode) and the September 16 renderer-constructs-HTML class, moved to the codegen phase: sanitize-order bugs mean the *sequence* of normalization passes is the specification, and each reorder is a new bypass surface.
  - Harness: owned OpenAPI description, one fixture per reformation shape, diff generated `.java`/`.php` AST for statements appearing outside comment nodes. Stop at "marker escapes comment position"; compile-and-run only in a sandbox with no credentials.
- **Manifest emission fields inherit the generator's trust blind spot.** `x-ai-capabilities.response_semantics.oauth_card_path` was copied verbatim into generated API-plugin manifests with no safe-relative-path validation, while *sibling* fields (`static_template.file`) had already received the safe-file-reference validator in earlier fixes (GHSA-4jwf-m4wg-8p66 / GHSA-p5rm-jg5c-8c77). Parent-traversal, rooted paths, and absolute URIs flow into the manifest; the harm fires at the downstream host that resolves the reference (package boundary escape or attacker-named auth card).
  - Durable rule: **when a generator previously fixed one emission field with a validator, enumerate every *other* emitted path/reference field and check whether the same validator runs at that emission site** — validators attach per-field, not per-schema. The advisory itself warns: "Do not rely on validation of sibling manifest fields to validate this field." Operator probe on any generated AI-plugin/manifest artifact: grep the manifest for `../`, `/`, and `://` in every path- or URI-shaped key, and separately confirm whether the host that consumes the manifest resolves them.

Both legs extend the page's core invariant — *generated source is attacker-influenced whenever the input artifact is* — with the phase split that matters for reporting: Kiota 1.x generation from an untrusted description proves unsafe emission; compiling, loading, or deploying that output is a separate, pipeline-dependent execution edge.
