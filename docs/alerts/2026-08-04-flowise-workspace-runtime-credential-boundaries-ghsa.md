---
title: Flowise workspace, runtime, and credential-authority boundaries
---

# Flowise workspace, runtime, and credential-authority boundaries

Thirty-one Flowise advisories published on August 4, August 7, August 8, and August 10 expose a useful low-code/agent-platform review pattern: a flow-builder permission or public prediction route is not authority over every workspace file, flow type, runtime loader, child-process environment, execution-context property, outbound destination, OAuth credential, integration history, document store, execution record, provider-funded feature, or billing object that a later component can select. Validate each edge independently with disposable objects and recorder-only sinks.

Most August 4 records list `flowise <= 3.1.2` as affected and `3.1.3` as the first patched release. The private-chatflow TTS record instead lists `flowise <= 3.1.3` as affected and `3.1.4` as fixed. Three August 7 records and the August 8 cloud-metadata deny-list record describe behavior through 3.1.4; the OAuth route record is explicitly a bypass of CVE-2026-41273. The JavaScript sandbox, MCP environment-bypass, and prompt-to-Python records also identify `flowise-components` ranges. Confirm the package-specific range in each advisory rather than assuming one release covers every server and component path.

Primary sources:

- JavaScript sandbox escape [GHSA-wg86-r78f-74mp / CVE-2026-69253](https://github.com/advisories/GHSA-wg86-r78f-74mp), the [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wg86-r78f-74mp), [fix PR 6417](https://github.com/FlowiseAI/Flowise/pull/6417), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/3f257bdc8196082a178da7134a075824401b13b9);
- cross-workspace file authorization [GHSA-wp74-f5hh-5f3r / CVE-2026-69252](https://github.com/advisories/GHSA-wp74-f5hh-5f3r), [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wp74-f5hh-5f3r), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/bc22bf8baec95b6a3d6e1b3563b4f03491cd6fbb);
- TypeORM `DataSource` option injection [GHSA-g32j-mmxr-gfq5 / CVE-2026-69251](https://github.com/advisories/GHSA-g32j-mmxr-gfq5) and the [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-g32j-mmxr-gfq5);
- public OAuth2 refresh and credential-bound outbound request [GHSA-r745-8hwv-h473 / CVE-2026-69250](https://github.com/advisories/GHSA-r745-8hwv-h473), [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-r745-8hwv-h473), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/da8b251a9a4c59484ceaf6f71df7406aede7bef2); and
- customer-source object authorization [GHSA-2364-jh4q-m9vm](https://github.com/advisories/GHSA-2364-jh4q-m9vm), [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-2364-jh4q-m9vm), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/4d7899d02ca370a5510406be5c91483085a412f9);
- SQLite Record Manager path override [GHSA-x3hf-7cj6-3r4m / CVE-2026-69259](https://github.com/advisories/GHSA-x3hf-7cj6-3r4m);
- unauthenticated prediction-context property injection [GHSA-6vh2-wg4h-4vwj / CVE-2026-69258](https://github.com/advisories/GHSA-6vh2-wg4h-4vwj);
- IPv4-mapped IPv6 SSRF-policy bypass [GHSA-c6xh-wv4j-ppv5 / CVE-2026-69257](https://github.com/advisories/GHSA-c6xh-wv4j-ppv5);
- CSV Agent `pandas.read_pickle()` sink selection [GHSA-x6vm-w76m-8j7g / CVE-2026-69256](https://github.com/advisories/GHSA-x6vm-w76m-8j7g);
- CSV Agent generated-Python string breakout [GHSA-vmv7-4m6c-3cg5 / CVE-2026-69255](https://github.com/advisories/GHSA-vmv7-4m6c-3cg5);
- caller-controlled `NodeVM` security options [GHSA-3769-jgqc-cxm7 / CVE-2026-69254](https://github.com/advisories/GHSA-3769-jgqc-cxm7);
- cross-type flow deletion [GHSA-p5w8-m249-4r4v / CVE-2026-69262](https://github.com/advisories/GHSA-p5w8-m249-4r4v), the [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-p5w8-m249-4r4v), [fix PR 6445](https://github.com/FlowiseAI/Flowise/pull/6445), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/2f528ceced74afaa95fc7a282965e7788796448b);
- MCP child-process environment bypass [GHSA-xc48-889x-5qmw / CVE-2026-69263](https://github.com/advisories/GHSA-xc48-889x-5qmw), the [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-xc48-889x-5qmw), [fix PR 6471](https://github.com/FlowiseAI/Flowise/pull/6471), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/a4c4e4988cded15edf725e762560575b889ae351);
- OAuth2 credential lookup and callback/refresh scope [GHSA-wch5-xp77-fxg4 / CVE-2026-70474](https://github.com/advisories/GHSA-wch5-xp77-fxg4);
- schema-dependent credential redaction [GHSA-rwrp-9823-p2xq](https://github.com/advisories/GHSA-rwrp-9823-p2xq);
- server-wide upsert-history disclosure [GHSA-fr6g-7cq8-fg82 / CVE-2026-70473](https://github.com/advisories/GHSA-fr6g-7cq8-fg82);
- OpenAI Assistants vector-store credential IDOR [GHSA-chm3-vqcf-52rx / CVE-2026-70472](https://github.com/advisories/GHSA-chm3-vqcf-52rx);
- CSV Agent data-URI source interpolation [GHSA-4j8x-x6v7-w9rq / CVE-2026-69264](https://github.com/advisories/GHSA-4j8x-x6v7-w9rq);
- S3 document-loader object-key traversal [GHSA-88pr-878c-24wf](https://github.com/advisories/GHSA-88pr-878c-24wf);
- runtime-variable permission bypass [GHSA-8r8h-6vcc-xhrv / CVE-2026-70471](https://github.com/advisories/GHSA-8r8h-6vcc-xhrv); and
- Pyodide validator Unicode-normalization bypass [GHSA-52fh-8v99-63c2 / CVE-2026-70470](https://github.com/advisories/GHSA-52fh-8v99-63c2);
- unauthenticated OAuth refresh-token response [GHSA-qgvm-j2hm-6m38 / CVE-2026-70478](https://github.com/advisories/GHSA-qgvm-j2hm-6m38);
- CSV Agent prompt-to-Python validator bypass [GHSA-5xvg-pmgg-3mxr / CVE-2026-70477](https://github.com/advisories/GHSA-5xvg-pmgg-3mxr);
- cross-tenant subscription selector [GHSA-gmmw-qg98-6j6p / CVE-2026-70476](https://github.com/advisories/GHSA-gmmw-qg98-6j6p);
- unauthenticated private-chatflow TTS credential use [GHSA-8gj2-2cvc-6xx7](https://github.com/advisories/GHSA-8gj2-2cvc-6xx7);
- execution-update authorization gap [GHSA-fm2f-4339-4p2f / CVE-2026-70475](https://github.com/advisories/GHSA-fm2f-4339-4p2f);
- prefix-whitelist OAuth refresh bypass [GHSA-rm9r-9424-cccf / CVE-2026-70636](https://github.com/advisories/GHSA-rm9r-9424-cccf) and the [research record](https://github.com/Caycon/cve-advisories/blob/main/2026/Flowise/CVE-2026-70636.md);
- OpenAI Assistants credential IDOR [GHSA-qvmw-v4w9-7c4j / CVE-2026-67622](https://github.com/advisories/GHSA-qvmw-v4w9-7c4j) and the [research record](https://github.com/Caycon/cve-advisories/blob/main/2026/Flowise/CVE-2026-67622.md); and
- view-only document-store mutation [GHSA-7q53-9j99-gg5c / CVE-2026-67621](https://github.com/advisories/GHSA-7q53-9j99-gg5c) and the [research record](https://github.com/Caycon/cve-advisories/blob/main/2026/Flowise/CVE-2026-67621.md); and
- cloud-metadata deny-list gaps and redirect handling [GHSA-6h53-jfj2-fh9c / CVE-2026-67620](https://github.com/advisories/GHSA-6h53-jfj2-fh9c), the [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-67620), and the [VulnCheck record](https://www.vulncheck.com/advisories/flowise-ssrf-via-fetch-links-endpoint-incomplete-deny-list); and
- unauthenticated private Assistants-file download [GHSA-mf39-7j64-g95c / CVE-2026-71962](https://github.com/advisories/GHSA-mf39-7j64-g95c).

!!! warning "Disposable Flowise labs and inert recorders only"
    Use affected and corrected local instances, two synthetic workspaces, fake API keys and OAuth credentials, owned HTTP listeners, package indexes, and S3-compatible buckets, synthetic flows/CSV/SQLite/history fixtures, mocked payment-provider objects, and patched file/module/process/delete/provider loaders. Never enumerate customer or credential IDs, retrieve billing records or real integration histories, capture real OAuth secrets, delete flows or files, target metadata or internal services, deserialize unknown data, install an unknown package, load unknown JavaScript, or execute a command.

## Boundary map

| Surface | Initial authority | Detached selector or sink | Safe positive |
| --- | --- | --- | --- |
| `GET`/`DELETE /api/v1/files` | API key has an unrelated feature permission in workspace A | organization-wide listing and caller-supplied path select workspace B | B's marker reaches list/delete recorder under A's key |
| Record-manager and agent-memory nodes | builder may configure one database node | `additionalConfig` reaches TypeORM module-loading options | synthetic outside-node path reaches patched module-open recorder |
| Agent/tool base URL | builder may configure a URL | URL text is interpolated into generated JavaScript and reaches an in-process sandbox | inert grammar marker reaches evaluator recorder outside the intended string slot |
| OAuth refresh | credential creator stores provider configuration | public route selects credential ID, URL, and stored client authority | unauthenticated request triggers owned listener with fake markers and reflects its canary response |
| Customer default source | user has a valid Flowise session | query `customerId` selects a different provider object | mocked customer B reaches response recorder under user A |
| SQLite Record Manager | builder may configure one record manager | trailing object spread replaces the fixed database path | disposable sibling path reaches SQLite open recorder |
| Public prediction API | caller may submit input to one public flow | ungated `overrideConfig` replaces `chatId`, `sessionId`, history, or `$flow.*` values | synthetic foreign-session marker reaches context recorder |
| HTTP security policy | hostname passes URL checks | IPv4-mapped IPv6 survives as a different address kind | owned dual-stack canary produces a policy/transport mismatch |
| CSV Agent | builder may select CSV parsing behavior | generated Python string or preloaded `pandas` API reaches a code/deserialization sink | inert grammar or pickle-open marker reaches a denied sink |
| Custom-function sandbox | authenticated caller may supply code and data | caller `nodeVMOptions` replaces security-critical defaults | forbidden synthetic module name reaches require-policy recorder |
| `DELETE /api/v1/chatflows/:id` | API key may delete one flow type | shared route accepts either permission, then resolves by ID without binding target type | opposite-type ID reaches a no-op delete recorder |
| MCP server launch | caller may choose a permitted interpreter and arguments | inherited/caller environment recreates blocked CLI behavior | safe package selector reaches a denied package/process recorder without a blocked flag |
| OAuth authorize/callback/refresh | caller can enter one OAuth phase | credential ID or callback `state` resolves without workspace/auth binding | workspace B fake credential reaches provider/update recorder under A or no session |
| Credential read API | role may view credential metadata | redaction follows UI field type instead of secret semantics | fake secret in a string-shaped field survives response projection |
| Upsert history | user may inspect one workspace's ingestion jobs | unscoped query returns server-wide integration records | workspace B history marker appears under A without downloading bulk data |
| Assistants vector-store API | role may use the assistants feature | query credential ID selects another workspace's provider authority | B's fake provider token selects mocked B objects under A |
| CSV/Pyodide validator | builder may provide CSV/node data | raw data-URI segment or Unicode-normalized identifier changes generated Python | inert marker changes AST or affected/fixed validator decision |
| S3 document loader | builder may read one owned bucket prefix | object key is joined to a local temporary directory | escaped marker reaches denied write-path recorder |
| Custom-function variables | role may run a function without `variables:view` | runtime injects all workspace/static environment-backed variables | random synthetic variable appears in sandbox-input recorder |
| OAuth refresh response | public route may initiate one refresh by credential ID | provider token response is returned to an unauthenticated caller | fake access-token marker reaches response projector |
| CSV Agent LLM output | caller may ask a question about one CSV | generated Python passes a token blacklist and reaches host-capable Pyodide | inert AST marker reaches denied evaluator/bridge recorder |
| Subscription update | organization member may manage its own plan | caller-supplied subscription ID selects another tenant's provider object | synthetic B subscription reaches no-op provider under A |
| Text-to-speech generation | public route may serve a public chatflow | arbitrary chatflow ID selects a private flow's stored provider authority | private-flow fake key reaches mocked TTS dispatch |
| Execution update | authenticated user may access some execution operations | update route omits operation permission and accepts caller-selected execution ID | foreign-role synthetic execution reaches no-op update recorder |
| OAuth refresh whitelist | public middleware admits one exact callback/refresh shape | prefix matching admits a longer credential-bearing route | synthetic request suffix selects B's fake credential and reaches only an owned provider recorder |
| Assistants credential selector | workspace member may use its own OpenAI Assistants integration | caller-supplied credential UUID is not bound to the active workspace | A selects B's fake credential and reaches mocked metadata/file/vector-store operations |
| Document-store refresh/upsert | view-only member may inspect a knowledge base | sibling mutation routes omit operation permission | viewer reaches a no-op ingestion/refresh recorder for a synthetic store |
| Fetch-links and URL-loading nodes | caller may submit a URL to an enabled flow | incomplete provider-address deny lists or redirects change the final peer after the initial decision | owned redirector reaches only an isolated synthetic destination and records the policy/peer mismatch |
| `POST /api/v1/openai-assistants-file/download` | no session can reach a globally whitelisted route | `chatflowId`, `chatId`, and `fileName` select a private file across workspaces | B's synthetic file identity reaches a denied read/relay recorder under no session |

## 1. Diff feature gates, permissions, and storage scope

The `/api/v1/files` record separates three decisions that are often incorrectly treated as one:

1. the organization plan enables the files feature;
2. the API key has permission to perform a specific file operation; and
3. the selected path belongs to the key's active workspace.

The affected route enforced only the first decision. Listing used the active organization root, while deletion accepted a path under that organization; the active workspace was not the storage authorization boundary.

### Two-workspace fixture

Create one organization with workspaces A and B. Place a uniquely named plain-text marker in each workspace. Issue an API key for A with only an unrelated read permission. Patch the delete function so it records the resolved object and returns a sentinel without unlinking anything.

Run this matrix against 3.1.2 and 3.1.3:

| Key | Operation | Selected marker | Secure result |
| --- | --- | --- | --- |
| A, file permission | list | A | allowed control |
| A, unrelated permission | list | A | denied |
| A, unrelated permission | list | B | denied and B absent |
| A, file permission | delete recorder | A | allowed control |
| A, unrelated permission | delete recorder | B | denied before resolution |
| A, file permission | traversal/sibling-shaped synthetic path | outside workspace | rejected before storage call |

Capture the key's permission set, organization and workspace IDs, route middleware decisions, requested path, canonical storage key, selected workspace, and whether the list/delete sink ran. A 200 response alone is weak evidence. The bounded positive is **A-only unrelated key -> B marker appears in the organization-wide listing or reaches the no-op deletion sink -> fixed build denies before storage access**.

Do not perform real deletion. Keep path confinement and workspace authorization as separate findings if both fail.

## 2. Treat structured library options as a module-loader interface

The TypeORM advisory identifies record-manager and agent-memory nodes that forwarded user-controlled `additionalConfig` into `DataSource`. TypeORM options such as `entities`, `subscribers`, and `migrations` can select local JavaScript modules. A field presented as database configuration can therefore become a host module-loader selector.

### Recorder-first workflow

1. Build an affected local Flowise instance with a disposable builder account and one synthetic flow.
2. Place a non-executable marker file inside the flow fixture and another in a disposable sibling directory. Neither file should contain JavaScript syntax.
3. Replace or wrap TypeORM's glob expansion and module import boundary so it records the raw option, expanded paths, canonical paths, and loader call, then raises a sentinel before reading or evaluating a file.
4. Configure each affected node family with ordinary database settings as the control.
5. Vary `additionalConfig` by value type: omitted, empty object, expected safe scalar, array, relative marker path, absolute marker path, glob-shaped marker, and symlinked path.
6. Trigger only the operation needed to initialize the `DataSource`; abort before connecting to a production-like database or loading a module.
7. Repeat against 3.1.3 and compare both accepted option keys and loader reachability.

A reportable positive is **builder-controlled structured option -> TypeORM resolves a synthetic out-of-node file -> patched import recorder receives that path**. Do not execute a module or claim command execution solely because the option is accepted. Record the exact node type and lifecycle event, because an option stored in flow JSON may not reach `DataSource` until upsert, memory initialization, or another runtime action.

Search other low-code integrations for the same pattern:

```text
...additionalConfig
...extraOptions
...driverOptions
...entities / subscribers / migrations
object spread into constructor options
```

Compare the caller-visible schema with the full downstream library schema. Any unrestricted object spread into a library that supports callbacks, plugins, files, modules, sockets, or commands deserves a sink inventory.

## 3. Split code construction from sandbox escape

The JavaScript advisory documents a chain in which a URL-shaped node field was inserted into generated JavaScript and then evaluated through an in-process sandbox. It also shows why dependency-level input checks can behave differently when they receive attacker-controlled objects inside a JavaScript sandbox.

Keep the chain as two independently proved edges:

```text
builder-controlled base URL
  -> generated-source string context changes
  -> evaluator receives altered source

sandbox value/object capability
  -> allowed dependency consumes attacker-controlled object method
  -> module resolution escapes the intended sandbox boundary
```

### Safe source-generation differential

Instrument the function that constructs and evaluates agent/tool JavaScript. Submit:

- a normal owned HTTPS URL;
- URLs with query and fragment markers that are valid according to the application's parser;
- quote, line-break, and comment-shaped **inert grammar markers** that contain no executable statement; and
- duplicate or normalized URL forms.

Record the parsed URL components, generated source bytes, source AST if available, evaluator options, allowed modules, and sandbox selection. Replace evaluation with a parser/recorder that refuses to run the source.

The first edge is positive only if the marker changes the generated AST or leaves the intended string literal. URL acceptance by itself is not code injection.

### Safe sandbox-capability differential

Use a separate same-process harness with a fake dependency and fake locale/module resolver. The dependency should expose a validator that calls a method on a supplied object; the resolver should record a random synthetic module name and abort. Compare primitive strings with string-like objects whose methods are overridden, without referencing host paths or executable files.

The second edge is positive when an attacker-defined object method changes a trusted dependency's validation result and the synthetic name reaches the recorder outside the expected module namespace. Do not load a host file. Do not combine the two edges into runtime execution unless the authorized lab independently proves both with denied final sinks.

Evidence should state whether the affected path used the legacy in-process sandbox, an external sandbox, or no sandbox. Updating one sandbox package does not establish that every Flowise component stopped selecting a different execution path.

## 4. Bind OAuth refresh authorization, object identity, and outbound authority

The OAuth record describes a refresh route under `/api/v1/oauth2-credential/refresh/:credentialId` that was publicly reachable, loaded stored credential data by ID, sent a server-side POST to the stored `accessTokenUrl`, and reflected the remote response body. The important chain is not generic SSRF; it is a stored credential acting as a capability that a lower-trust caller can spend.

### Fake-credential harness

Use a local Flowise lab, an owned HTTP listener, and one synthetic OAuth credential whose client ID, client secret, and refresh token are obvious fake canaries. Ensure the listener has no path to metadata, RFC1918 services, or production networks.

Test independently:

| Caller | Credential selector | Token authority | Expected |
| --- | --- | --- | --- |
| authorized owner | own synthetic ID | owned listener | allowed control |
| no session | nonexistent ID | none | generic denial |
| no session | own synthetic ID | owned listener | denied before credential decrypt/fetch |
| user A | user B's synthetic ID | owned listener B | denied by object ownership |
| owner | own ID with redirect to second owned listener | two owned authorities | redirect policy recorded and bounded |

At the listener, record only the presence and length of named fake fields, never reusable values. Return a random JSON canary and compare whether it appears in the Flowise response. Capture route-auth decision, credential owner/workspace, selected URL, redirect chain, final authority, request field names, and response-reflection behavior.

A strong bounded positive is **unauthenticated request names a valid synthetic credential -> Flowise decrypts it -> owned listener receives fake credential fields -> listener canary is reflected to the caller**. Report outbound reach, stored-secret relay, and response read as separate effects. Never substitute a metadata or internal-service URL.

Generalize this review to callback, refresh, test-connection, webhook-replay, and provider-health routes. A route may need public reach for one phase, but that does not grant anonymous authority to select and spend an existing credential object.

## 5. Keep provider-object IDOR proofs synthetic

The customer-source advisory states that an authenticated request could supply a different `customerId` to `/api/v1/organization/customer-default-source`. Because real provider responses may contain email and billing metadata, do not validate this by guessing or enumerating live Stripe-style IDs.

Use a mocked provider adapter with customers A and B, each containing only random marker fields. Log the authenticated Flowise user, active organization, requested customer ID, provider object selected, authorization object, and response fields. Exercise same-user, foreign-user, foreign-organization, malformed, omitted, and nonexistent IDs.

The positive is **user A's session -> caller-supplied B ID -> mocked provider returns B -> Flowise response recorder receives B's marker without an ownership decision**. The fixed build should derive the customer ID from A's authorized organization/customer relation or explicitly compare the supplied object before calling the provider.

Do not claim predictable-ID enumeration without measuring the actual identifier source in a synthetic environment. Never retain or publish real email, balance, invoice, payment-method, or provider-token data.

## Evidence and reporting checklist

- [ ] Exact Flowise and `flowise-components` versions, deployment mode, route, node type, role, feature plan, and workspace are recorded.
- [ ] Feature availability, operation permission, workspace scope, and path confinement are separate decisions.
- [ ] File deletion, module import, source evaluation, process creation, provider fetch, and payment lookup are recorder-only sinks.
- [ ] TypeORM evidence identifies the option key, resolved path, and lifecycle event that reaches the loader.
- [ ] Code-construction and sandbox-capability edges are proved separately with inert grammar/module markers.
- [ ] OAuth evidence uses fake secrets and distinguishes route auth, credential ownership, final outbound authority, secret-field relay, and response reflection.
- [ ] Customer-source evidence uses mocked provider objects and no identifier enumeration.
- [ ] Shared-delete evidence records the granted permission, resolved flow type, and a no-op sink; no flow is deleted.
- [ ] MCP launch evidence records effective arguments and environment and aborts before package resolution, install, or process start.
- [ ] OAuth and provider-tool evidence binds route phase, callback transaction, workspace, credential owner, operation, and mocked provider sink.
- [ ] Credential, variable, and history tests record only canary presence and stop after the first foreign marker.
- [ ] Generated-code evidence compares raw, normalized, validated, and parsed representations without evaluator or host-bridge execution.
- [ ] S3 loader evidence records canonical write and cleanup targets while denying every filesystem mutation.
- [ ] Affected-versus-3.1.3 behavior is captured with the same fixture.
- [ ] Route-whitelist tests compare exact, prefix, suffix, delimiter, encoded, and normalized path forms before any credential lookup.
- [ ] Assistants and document-store tests use two workspaces, marker-only objects, and no-op provider/ingestion sinks.
- [ ] URL-fetch evidence records every resolution, redirect hop, canonical address, and final peer using owned no-content services only.

Prefer boundary-specific report titles such as:

- **“Flowise API key with unrelated permission reaches a file in another workspace.”**
- **“Flowise record-manager options reach TypeORM's local module selector.”**
- **“Flowise agent-tool URL changes generated JavaScript structure before sandbox evaluation.”**
- **“Public Flowise refresh route spends a stored OAuth credential against its configured authority.”**
- **“Flowise customer-source route resolves a provider object not owned by the active organization.”**
- **“Flowise URL policy accepts an owned destination class that the final transport should deny.”**

Do not lead with remote code execution, secret exfiltration, or cross-customer disclosure unless the corresponding final edge is independently demonstrated under the safe boundaries above.

## 6. Test option precedence at the SQLite file boundary

The SQLite Record Manager record is narrower than the TypeORM module-selector issue: `additionalConfig` was spread after the intended `database` value, so a builder-controlled option could replace the database path itself. Treat this as an option-precedence and file-open test, not as an invitation to write an executable database.

Wrap the SQLite/TypeORM open call and record the configured database root, raw option object, final path, canonical path, open flags, and whether the target existed. Use an empty disposable directory with marker paths inside the intended root and a sibling temporary directory. Compare omitted, in-root, sibling, absolute, and symlink-shaped values. Abort before opening or creating the database.

A bounded positive is **builder-supplied `additionalConfig.database` -> final canonical path leaves the configured database root -> patched open recorder receives the sibling marker**. Separately record whether the container runs with elevated filesystem authority; do not infer host impact from a root UID inside a container.

## 7. Bind public prediction overrides to the authorized context schema

The prediction record identifies two ungated object spreads that could overwrite trusted flow-context fields even when node-input overrides were disabled. Build a public synthetic flow whose context consumer returns only random canaries and whose memory adapter is replaced by a read/write recorder.

Exercise an explicit property matrix:

| Property class | Examples | Secure result |
| --- | --- | --- |
| documented public input | ordinary prediction text | accepted |
| identity/session | `chatId`, `sessionId`, `chatflowId` | ignored or rejected |
| history/state | `chatHistory`, nested state marker | ignored unless explicitly enabled and schema-validated |
| template namespace | random `$flow.*` canary property | unavailable to downstream templates |
| structural keys | nested objects, arrays, prototype-shaped names | rejected before merge |

Use two disposable sessions and never place real prompts in either. Record the raw request, override feature flag, allowlisted keys, resolved context, memory selector, and template substitutions. The positive is **unauthenticated caller supplies session B's random ID or history marker -> session/context recorder for B is selected while API overrides are disabled**. Do not retrieve or alter a real conversation.

## 8. Compare address policy with the final transport destination

Flowise's SSRF check compared address kinds before CIDR matching. An IPv4-mapped IPv6 result could therefore skip IPv4 ranges without being covered by the IPv6 deny entries. Test this only with owned loopback-equivalent canary listeners in an isolated network namespace.

Record every DNS answer, parsed address kind, normalized address, matched policy range, socket family, and final peer address. Include ordinary IPv4, ordinary IPv6, IPv4-mapped IPv6, unspecified forms, redirects between owned authorities, and a rebinding-style second answer served by an owned resolver. The secure invariant is that every accepted destination is normalized to a canonical address class and rechecked at each connection.

A useful report shows **policy parser accepts the mapped form -> transport recorder resolves it to the denied canary destination -> corrected build rejects both spellings**. Never substitute cloud metadata, a local admin service, or an internal production address.

## 9. Separate generated-code, deserialization, and sandbox-option edges

The CSV Agent records expose two independent edges: untrusted data embedded into generated Python source, and a caller-selected `pandas` operation reaching a pickle deserializer despite keyword denylisting. The `NodeVM` record adds a third: caller options spread after secure defaults can replace the module policy.

Use three denied-sink harnesses rather than a shell payload:

1. **Generated Python:** replace Pyodide execution with a parser and AST recorder. Feed CSV data containing inert quote, newline, and comment markers. Report only if the marker leaves the intended string literal or changes the AST.
2. **Deserializer selection:** wrap `pandas` parser dispatch and pickle loading. Supply a locally generated pickle containing only a random scalar marker; abort at the pickle-open boundary. Report the selected API and bytes provenance, not code execution.
3. **Sandbox options:** wrap `NodeVM` construction and module resolution. Supply a random nonexistent built-in name through `nodeVMOptions`; deny resolution and compare the final effective options with secure defaults.

Keep the conclusions precise: generated-source injection, unsafe deserializer reachability, and security-option replacement are separately reportable. Claim sandbox escape or host execution only when an authorized isolated lab independently proves the final boundary without reusable payloads or sensitive output.

## 10. Bind a shared delete route to the selected flow type

The cross-type deletion record is a reusable warning about `checkAnyPermission(...)`: passing one member of a permission union does not authorize every object family handled by the route. The affected `/api/v1/chatflows/:id` path accepted either `chatflows:delete` or `agentflows:delete`, resolved the target by `id` and workspace, and deleted without comparing the target's type with the permission that admitted the request.

### No-op object-type matrix

Use one disposable workspace, one synthetic `CHATFLOW`, one synthetic `AGENTFLOW`, and API keys that carry exactly one delete permission each. Replace the repository delete call with a recorder that returns a sentinel without changing either object.

| Key permission | Selected object | Secure result |
| --- | --- | --- |
| `chatflows:delete` | synthetic `CHATFLOW` | reaches no-op recorder as an allowed control |
| `chatflows:delete` | synthetic `AGENTFLOW` | denied before delete lookup/sink |
| `agentflows:delete` | synthetic `AGENTFLOW` | reaches no-op recorder as an allowed control |
| `agentflows:delete` | synthetic `CHATFLOW` | denied before delete lookup/sink |
| either permission | foreign-workspace flow | denied by workspace scope |
| neither permission | either local flow | denied by route middleware |

Capture the authenticated principal, exact permission set, active workspace, route family, requested ID, resolved object's stored type, authorization branch, and whether the no-op sink ran. Compare the same fixture on 3.1.2 and 3.1.3. A bounded positive is **single-type delete permission -> opposite-type synthetic object resolves -> recorder receives its ID without a type-specific authorization decision**.

Never send a real `DELETE` to a retained flow. Do not infer cross-workspace impact from the type mismatch; prove workspace scope separately. Search adjacent shared CRUD routes for the same pattern whenever middleware grants `typeA:operation OR typeB:operation` but the repository query selects only by ID.

## 11. Diff CLI flags and child-process environment as one policy surface

The MCP follow-up shows why blocking `npx -y` is incomplete when caller-controlled environment reaches the same process. `npm_config_*` variables can configure npm behavior without a corresponding command-line flag, while permitted interpreters have other environment-controlled loaders. Treat executable, arguments, environment, working directory, package source, and inherited process state as one launch decision.

### Denied-launch harness

Prerequisites are an affected local Flowise instance with `CUSTOM_MCP_SECURITY_CHECK=true`, an owned empty package index, a random nonexistent package name, and wrappers around package resolution and child-process creation. The wrappers must record normalized launch inputs and abort before network download, package installation, module loading, or process start.

Run this differential:

| Executable and input | Expected secure result |
| --- | --- |
| permitted interpreter with ordinary inert arguments and minimal allowlisted environment | allowed control reaches only the no-op process recorder |
| `npx` plus blocked confirmation flag | rejected before package resolution |
| `npx` without that flag plus an environment value that enables equivalent non-interactive behavior | rejected before package resolution |
| `node`/`python3` plus environment-controlled synthetic module-path selector | rejected before module lookup |
| mixed-case, duplicate, empty, inherited, and nested environment representations | canonicalized, then rejected or reduced to an explicit allowlist |

Record the raw MCP configuration, executable identity, argument vector, raw and effective environment, inherited variables, working directory, package-index authority, package selector, and first reached recorder. Never use a public package name: dependency confusion or a changed package owner can turn an inert test into code execution.

The reportable positive is **blocked CLI behavior absent from `args` -> equivalent environment configuration survives validation -> owned package/process recorder shows the same launch decision on 3.1.2 -> 3.1.3 rejects before resolution**. This proves a policy bypass without installing or executing a package. Keep unauthenticated route reachability, environment-policy bypass, package resolution, installation, and runtime execution as separate edges; claim the strongest edge actually captured.

Generalize the review beyond npm. For every allowed launcher, enumerate configuration channels from vendor documentation, then compare policy coverage across CLI flags, environment variables, config files, shebangs, working-directory files, and inherited state. A denylist that covers only one representation is a variant-analysis seed, not a complete execution boundary.

## 12. Bind every OAuth phase and provider tool call to one credential owner

The later OAuth and Assistants records widen the earlier refresh-route finding. Authorization, callback, refresh, and provider-tool routes can all resolve the same credential through different selectors, yet each route may apply a different authentication and workspace decision. Callback `state` is correlation data, not proof that the caller may update the credential it names. Likewise, permission to use an Assistants feature is not permission to spend any credential ID supplied in a query.

Create workspaces A and B with one fake OAuth credential and one mocked OpenAI-style credential each. Use distinct random IDs and canary fields. Replace provider exchange, credential update, vector-store list/create/delete, and file operations with recorders that never contact a real provider or persist a token. Exercise this matrix:

| Caller and phase | Selected credential | Secure result |
| --- | --- | --- |
| A owner, authorize | A | owned provider recorder reached |
| A owner, authorize | B | denied before provider URL construction |
| no session, callback with synthetic `state` | B | callback correlation may parse, but no B update without a bound transaction |
| no session, refresh | B | denied before decrypt/provider call |
| A with Assistants permission | B | denied before credential decrypt or mocked vector-store call |
| B owner, provider tool | B | allowed control |

Record the route, authentication state, active workspace, raw selector, callback transaction/nonce, credential owner, decrypt decision, outbound authority, mocked provider operation, and update sink. A bounded positive is **A or no session names B's synthetic credential -> B reaches a provider or update recorder without an owner-bound authorization decision**. Do not return or log fake token values beyond a one-way marker match, and never repeat this with a real OAuth or OpenAI credential.

Review all credential-consuming routes, not just credential CRUD. Search controllers and services for `credentialId`, callback `state`, `findOneBy({ id`, decrypt helpers, refresh/test-connection actions, and provider constructors. The invariant is one tuple carried end to end: **authenticated principal + active workspace + credential ID + permitted operation + callback transaction**, with no phase silently dropping a member.

## 13. Test response projection, variable injection, and history scope with canaries

The credential-redaction, runtime-variable, and upsert-history records share one mistake: a principal is allowed to receive *some* object fields, sandbox inputs, or history rows, then the response is built from a broader internal representation.

### Field-semantics redaction matrix

Build synthetic credential definitions where identical random secret markers appear in `password`, ordinary `string`, multiline JSON, URL userinfo, nested object, and array fields. Call only the credential-read API with a lab role carrying the minimum view permission. Capture field names and whether each marker survives; do not print the marker values. A secure response uses an explicit public projection and secret semantics, not a UI widget type, to decide what leaves the server.

### Variable injection matrix

Create one public marker, one static secret-shaped marker, and one runtime variable mapped to a fake environment variable. Use separate roles with and without `variables:view`, and replace custom-function evaluation with a sandbox-input recorder. Compare the official Variables API with every custom-function, template, and prediction path that injects `$vars`. A positive is **role denied by the Variables API -> forbidden marker is still present in the evaluator input**. Stop before evaluating code.

### Two-workspace history matrix

Seed one minimal upsert-history row per workspace with only random collection and endpoint markers. Patch serialization to stop after the first foreign row so the test cannot become a bulk download. Compare A querying its own document/store context, A supplying B-shaped selectors, missing selectors, and an admin control. Record SQL/repository predicates, pagination, row workspace IDs, and response projection. The reportable positive is **A request -> query lacks workspace predicate -> B marker reaches the bounded serializer**.

Keep these as distinct findings when appropriate: missing row scope, overbroad response projection, missing operation permission, and excessive unbounded output are different boundaries. Never collect a production history, connection URL, private key, cloud key, prompt, or environment value as evidence.

## 14. Compare pre-validation text with post-normalization code

Two CSV Agent paths now provide complementary source-construction tests:

1. a raw segment extracted from a data URI reaches a generated Python string before base64/content validation; and
2. JavaScript regex deny rules inspect one spelling while Python normalizes Unicode identifiers before parsing.

Use a parser-only differential. Replace `runPythonAsync` and the JavaScript bridge with a recorder that stores a hash of the generated source, parses it in a constrained subprocess, records the AST node classes, and rejects execution. Generate inert inputs across these classes:

- valid base64 and malformed alphabet characters;
- comma-count and filename-segment variants in the data URI;
- quotes, line breaks, and comment-shaped markers with no statement or callable;
- ASCII identifiers and compatibility characters whose NFKC form is ASCII;
- precomposed/decomposed forms, mixed scripts, bidi controls, and zero-width characters; and
- the same corpus before and after NFKC normalization.

For each input, record the raw bytes, decoded components, validator decision, normalized form, generated-source hash, parser decision, and AST delta. A bounded positive is **validator accepts text -> downstream parser sees a different security-relevant token or the inert marker leaves its intended literal**. Do not include an import, host bridge, file operation, or command in the fixture.

This is a reusable variant-analysis rule: when validation and execution use different languages or normalization rules, validate the same canonical representation the final interpreter consumes. Prefer positive grammar/AST allowlists and structured argument passing over token blacklists.

## 15. Treat remote object keys as archive-member paths

The S3 Directory record is structurally equivalent to archive extraction: a remote object key becomes a relative local filename beneath a temporary root. Prefix authorization in the bucket does not confine the later filesystem write.

Use an owned S3-compatible test bucket and patch `mkdir`, write, rename, and cleanup calls to record canonical targets and return sentinels. Seed zero-content object keys for a normal child, nested child, `..` segment, absolute-looking form, repeated separators, Windows separator, Unicode separator lookalike, prefix sibling, and symlink-parent fixture. Run both directory and single-file loader modes because write and cleanup behavior can differ.

The secure decision must occur on the final filesystem path immediately before every create/write/rename/delete operation:

```text
candidate = canonical(temp_root + remote_key)
require candidate is a descendant of canonical(temp_root)
require no followed parent component escapes through a symlink
```

A strong bounded positive is **owned object key -> canonical target leaves the temporary root -> denied write recorder receives the outside marker**. Record cleanup targets separately; never allow the loader to create, overwrite, or delete the canary. Generalize this check to cloud prefixes, ZIP/TAR members, uploaded filenames, Git trees, and model artifacts that are materialized locally.

## 16. Separate OAuth route reachability from token response projection

The later refresh advisory adds a stronger final edge to the earlier OAuth route finding: the public refresh handler returned the provider's `access_token` structure to its caller. Prove this without obtaining or minting a usable token.

1. Configure one synthetic OAuth credential against an owned provider stub. Use random strings that no real provider will accept.
2. Have the stub return a JSON object with a one-time `access_token` canary and harmless expiry fields.
3. Compare no session, workspace A owner, workspace B user, malformed ID, and nonexistent ID requests.
4. Record route-auth, credential owner, decrypt decision, provider destination, response field names, and whether the canary reaches the response serializer. Store only a hash/presence bit for the canary.

A bounded positive is **no session -> valid synthetic credential ID -> owned provider receives the fake refresh fields -> fake access-token marker reaches the unauthenticated response**. This is distinct from a response that merely says “credential not found”: that proves route reachability, not token disclosure. Never use a real client secret, refresh token, or provider account.

## 17. Treat LLM-produced code as untrusted compiler input

The new CSV Agent record shows that an LLM response passed a regex blacklist and then reached Pyodide with host interfaces available. Do not replay published bypass strings or execute a command. Replace `runPythonAsync`, import hooks, filesystem calls, and host bridges with recorders that deny use.

Build a corpus of harmless programs that exercise aliases, concatenated identifiers, attribute lookup, decorators, dataframe expression APIs, Unicode normalization, and syntax nesting, but whose only intended effect is to emit a random AST marker. For each case, capture the prompt/input provenance, raw model text, normalized source, validator result, parsed AST node classes, selected dataframe APIs, and first denied capability. Compare deterministic mocked model output on 3.1.2 and 3.1.3 before trying nondeterministic prompt injection.

The reportable transition is **untrusted model output -> validator accepts a security-relevant syntax class outside the documented dataframe subset -> denied evaluator or host-bridge recorder is reached**. Keep prompt influence, validator bypass, evaluator reachability, and host capability as separate edges. No shell, network, package, or host-file payload is needed.

## 18. Bind provider-funded operations to the owning object

Subscription updates and text-to-speech generation are the same confused-deputy pattern at different authentication levels. A caller can request an operation, but the server must derive the Stripe-style subscription or TTS credential from an object the caller is authorized to use.

Use mocked providers only:

| Caller | Selected object | Mocked operation | Secure result |
| --- | --- | --- | --- |
| organization A member | A subscription | no-op plan/seat update | allowed control |
| organization A member | B subscription | no-op plan/seat update | denied before provider call |
| no session | public flow A | fake TTS dispatch | allowed only if public TTS is an intended feature |
| no session | private flow B | fake TTS dispatch | denied before credential lookup/decrypt |
| B owner | private flow B | fake TTS dispatch | allowed authenticated control |

Use random, non-provider-shaped IDs and marker-only provider adapters. Do not change a plan, quantity, quota, or generate billable audio. Capture principal, active organization/workspace, requested object ID, resolved owner/public flag, credential-decrypt decision, and mocked operation. A strong finding stops at **A/no session selects B -> B's fake provider authority reaches the no-op adapter**.

## 19. Authorize execution mutations before resolving update data

For the execution update route, seed two synthetic execution records with marker-only state and use roles with `executions:view`, `executions:delete`, unrelated permission, and no execution permission. Replace persistence with a recorder that logs the requested ID and changed field names, then aborts.

Test own and foreign-workspace IDs, omitted IDs, bulk-shaped bodies, immutable owner/workspace fields, and state/data metadata fields. The secure route must check `executions:update`, bind the object to the active workspace, and apply an explicit mutable-field schema before the update sink. A bounded positive is **role lacking update authority -> known synthetic execution ID -> no-op update recorder receives changed fields**. Never alter retained workflow history or place prompts, secrets, customer data, or executable content in the fixture.

## 20. Treat public-route whitelists as exact route grammars

The August 7 OAuth record describes an authentication bypass caused by prefix matching in the public-route whitelist. A route that must be anonymous for one OAuth phase should not make every longer path beginning with that string anonymous, especially when the suffix becomes a credential selector. This is a useful variant-analysis target after any route-level fix.

Build two fake credentials in workspaces A and B, both pointing to an owned provider stub. Patch credential decryption and provider dispatch so they record object identity and field names, then stop before returning or updating a token. Generate requests from the router's actual grammar rather than replaying a production token:

| Path class | Example shape | Secure result |
| --- | --- | --- |
| intended public route | exact documented callback or bootstrap path | admitted only for its public phase |
| credential-bearing child | public prefix plus `/synthetic-id` | authentication required before lookup |
| delimiter variants | extra slash, dot segment, semicolon, duplicate separator | canonicalized, then exact policy applied |
| encoded variants | encoded slash/dot and mixed-case escape | raw and decoded routing decisions agree |
| sibling prefix | same text with a longer final segment | not considered the public route |
| query/fragment-like text | selector outside the path grammar | cannot alter route classification |

Capture raw target bytes, proxy path, framework-decoded path, normalized route, matched whitelist entry, route parameters, principal, selected credential owner, and first recorder reached. A bounded positive is **no session + longer prefix-matching path -> workspace B's synthetic credential reaches the decrypt/provider recorder**. The corrected behavior denies before object resolution.

Do not rely on a 200 response or an error difference alone. Search every public-route exception for `startsWith`, regexes without end anchors, string-prefix middleware, mounted routers, optional parameters, and trailing wildcard behavior. Re-test the original patch and its alternate delimiters because CVE-2026-70636 is identified as a bypass of an earlier fix.

## 21. Bind Assistants operations to the credential workspace

The new Assistants record complements the earlier vector-store finding: the credential UUID can select provider authority from another workspace, after which multiple sibling handlers may expose metadata or perform file/vector-store operations. Treat each provider method as a separate authorization sink; do not prove a read by uploading or deleting anything.

Use workspaces A and B, each with a random credential UUID and a mocked provider containing only marker-named assistants, files, and vector stores. Give A the minimum Assistants feature permission. Replace list, metadata, upload, create, update, and delete methods with recorders; mutating recorders must return sentinels without changing state.

Test A's own UUID, B's UUID, a nonexistent UUID, a malformed UUID, an omitted selector, and an object whose workspace relation is missing. Record the active workspace, requested UUID, credential row workspace, decrypt decision, provider client construction, selected operation, and recorder arguments. Stop after the first B marker.

A reportable positive is **workspace A session + B credential UUID -> B's fake provider client reaches a metadata or no-op mutation recorder without a workspace comparison**. Report metadata listing, file selection, vector-store selection, and no-op mutation as separate effects. Never enumerate credential IDs, list real provider objects, upload a file, or spend a real API key.

## 22. Re-check operation permissions on document-store sibling routes

The document-store record shows API/UI permission drift: a member intended to view a store can call direct refresh or upsert routes that trigger ingestion, vector-database changes, and provider-funded embedding work. Hiding controls in the builder is not an authorization decision.

Seed one synthetic document store per workspace with marker-only documents and replace loader, embedding, vector write, refresh, and persistence calls with no-op recorders. Use roles with view-only, explicit edit/upsert, unrelated, and no document-store permissions. Exercise both documented UI calls and direct sibling routes with the same store IDs.

| Principal | Store | Operation | Secure result |
| --- | --- | --- | --- |
| editor A | A | no-op upsert/refresh | allowed control |
| viewer A | A | no-op upsert/refresh | denied before ingestion |
| viewer A | B | no-op upsert/refresh | denied before lookup or ingestion |
| unrelated A role | A | no-op mutation | denied |
| viewer A | A | metadata read | allowed only if view permission intends it |

Capture UI capability flags, route middleware, effective permission, requested and resolved workspace/store IDs, operation type, provider-cost boundary, and first no-op sink. A bounded positive is **view-only session -> direct mutation route -> loader/embedding/vector recorder receives A's synthetic store**. Keep missing operation permission and cross-workspace object scope separate. Do not ingest retained documents, alter a vector store, or generate billable embeddings.

## 23. Validate destination classes and redirects at the final peer

The August 8 record adds a second SSRF-policy failure mode to the IPv4-mapped IPv6 issue: a static deny list can omit provider-specific address space altogether. The advisory identifies Oracle Cloud Infrastructure's `192.0.0.192` and Alibaba Cloud's `100.100.100.200` metadata destinations, and says affected fetch-links paths could also retain reachability through redirects. Do **not** contact either metadata service. Use the addresses only as taxonomy seeds for reviewing how the policy represents destination classes.

### Isolated final-peer harness

Prerequisites are an affected local Flowise instance, a public chatflow only if anonymous reachability is in scope, an isolated network namespace, an owned redirector, and two no-content canary listeners bound only inside that namespace. Replace the transport connector where possible so it records the chosen peer and aborts before sending a request body.

Exercise this matrix with synthetic addresses assigned to the canary namespace rather than real cloud endpoints:

| Input class | Redirect behavior | Secure result |
| --- | --- | --- |
| ordinary owned HTTPS URL | none | allowed control reaches the owned listener |
| hostname resolving to a policy-denied synthetic subnet | none | denied after resolution and before connect |
| allowed owned URL | redirects to denied synthetic subnet | redirect rejected before the second connect |
| allowed owned URL | redirects across hostname, address family, or port | every hop is canonicalized and re-authorized |
| hostname with multiple answers | connector selects a later denied answer | selected peer is checked, not only the first DNS answer |
| public chatflow URL node | same owned fixtures | anonymous route authority does not weaken destination policy |

For each attempt, capture the route and authentication state, URL source, raw and parsed URL, DNS answer set, canonical address, matched policy class, redirect status and `Location`, selected socket peer, and first denied connector event. Keep the listener responses empty except for random status markers. The bounded positive is **initial URL passes -> owned redirect or alternate answer selects the denied synthetic destination -> affected build reaches the connector recorder -> corrected policy rejects before connect**.

This workflow distinguishes three findings that should not be collapsed:

1. **coverage gap:** a destination class is absent from policy;
2. **redirect gap:** only the initial URL is authorized; and
3. **connect gap:** DNS is checked, but the actual selected peer is not rebound to the decision.

A static list containing well-known metadata IPs is not proof of complete SSRF control. Inventory cloud-specific IPv4, IPv6, link-local, alias-hostname, and provider-proxy classes from current provider documentation, but perform validation only with synthetic equivalents. Reapply the same canonical policy after each redirect and immediately before every connection. Never query a real metadata path, request an identity document, retrieve a role credential, or probe an internal service.

## 24. Bind anonymous download routes to public objects and file ownership

The August 10 record describes `POST /api/v1/openai-assistants-file/download` as present in the global authentication whitelist while accepting `chatflowId`, `chatId`, and `fileName` selectors. This is not merely a filename-confinement check: route authentication, chatflow visibility, chat/session ownership, file ownership, storage path, and response relay are independent decisions.

Create workspaces A and B with one public synthetic flow in A, one private synthetic flow in B, one random chat ID each, and marker-named empty files. Replace storage lookup, file open, provider download, and response streaming with recorders that return no bytes. Test no session, A, and B against own, foreign, nonexistent, malformed, omitted, duplicated, traversal-shaped, and cross-combined flow/chat/file selectors.

Capture raw and normalized route, whitelist match, principal, active workspace, requested IDs, resolved flow visibility/owner, chat owner, file owner, canonical storage key, and first read/relay recorder. A bounded positive is **no session -> B private `chatflowId`/`chatId`/`fileName` -> B's synthetic file reaches the denied read or response recorder without authentication and ownership checks**. Identifier acceptance or status differences alone are insufficient.

Keep anonymous reachability, cross-workspace IDOR, and path traversal as separate findings. Do not enumerate IDs, retrieve a real file, return marker bytes, list provider objects, or test customer chat history. The fixed route should either leave the global whitelist or bind an intentionally public download capability to one flow, chat, file, audience, and expiry before any storage/provider call.

## September 16 note: historical `overrideConfig` advisory and duplicate marking (2 GHSAs)

The updated feed re-surfaced the 2024 Flowise `overrideConfig` advisory [GHSA-5cph-wvm9-45gj](https://github.com/advisories/GHSA-5cph-wvm9-45gj) with a June 2026 duplicate [GHSA-5w6g-rc45-wvv9](https://github.com/advisories/GHSA-5w6g-rc45-wvv9). It documents the original design flaw — prediction-API/web-embed `overrideConfig` reaching execution context (sandbox escape, SSRF, prompt injection) — with the vendor remedy of disabling or allow-listing `overrideConfig` by default. Section 7 above already prescribes the replayable check (ungated spreads overwriting `chatId`/`sessionId`/`$flow.*` context with canary markers). No new workflow; marked processed. Historical-advisory resurfacing is still an engagement signal: many deployed Flowise instances predate the fix, so enumerate `overrideConfig` acceptance on any live prediction route you are authorized to test.
