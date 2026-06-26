# Google-style API black-box recon

Sources: Brutecat Security / Arvin Shivram — [Decoding Google: Converting a Black Box to a White Box](https://brutecat.com/articles/decoding-google), [Leaking the email of any YouTube user for $10,000](https://brutecat.com/articles/leaking-youtube-emails), [Disclosing YouTube Creator Emails for a $20k Bounty](https://brutecat.com/articles/youtube-creator-emails), [Leaking the phone number of any Google user](https://brutecat.com/articles/leaking-google-phones), [StubZero: $148,337 RCE in Google Cloud Production](https://brutecat.com/articles/google-cloud-rce), and [Hacking Google with A.I. for $500,000](https://brutecat.com/articles/hacking-google-with-ai).

Brutecat's Google research shows a repeatable operator pattern for very large API estates: convert opaque product traffic into typed service definitions, classify authentication and origin gates, then test only authorized state-changing or privacy-sensitive paths with minimal proofs. The durable technique is not any single Google endpoint; it is the workflow for turning scattered web, Android, protobuf, discovery-document, and error-message artifacts into a map of reachable methods and trust boundaries.

!!! warning "Authorized testing only"
    Use this playbook only for owned systems, explicitly scoped bounty programs, or lab replicas. Do not enumerate private users, recover account identifiers, bypass anti-abuse controls, or brute-force personal data outside written authorization. For identity-recovery and PII flows, keep testing to accounts you control and stop at controlled proof.

## When to use this playbook

Use it when a target has:

- Many first-party APIs spread across product subdomains, mobile apps, staging hosts, or client-specific frontends.
- Machine-readable API descriptions: OpenAPI, Discovery documents, GraphQL SDL, protobuf descriptors, gRPC reflection, generated clients, or source maps.
- Client-context gates such as API keys, package signatures, mobile app IDs, origin/referer allowlists, feature flags, or tenant/project labels.
- Structured error responses that reveal auth stage, method names, expected types, missing scopes, or backend service names.
- Cross-product account identifiers, resource IDs, content-owner IDs, tenant IDs, workflow IDs, or opaque base64/protobuf parameters.

## Source-to-technique map

| Brutecat article | Reusable technique |
| --- | --- |
| Decoding Google | API-key and app-context authentication mapping; hidden discovery labels; Android app context; X-Goog-Spatula-style project context; ProtoJson type-confusion to leak request shapes. |
| YouTube email leak | Base64/protobuf parameter decoding; channel-to-account identifier pivot; stale/forgotten product as resolver for a sensitive identifier. |
| YouTube creator email leak | ProtoJson array probes to recover hidden parameters; API Explorer/client-context mismatch; Content Owner / IVP object pivot. |
| Google phone leak | Identity-recovery oracle testing; rate-limit and anti-abuse boundary review; country/format pruning with libphonenumber; controlled false-positive filtering. |
| Google Cloud RCE / StubZero | Debug endpoint to proto-definition leak; response-format switching; workflow/task configuration abuse; internal RPC/stubby authorization-boundary modeling. |
| Hacking Google with A.I. | Large-scale discovery-doc corpus; API-key collection and restriction taxonomy; AI-assisted endpoint classification; multi-key probing; GraphQL scalar-field fuzzing; feature-flag UI surfacing. |

## 1. Build a client-context corpus

Collect the client contexts that the target itself exposes. Treat each key, package, origin, mobile signature, and API host as a scoped capability, not as a secret to leak.

High-value sources:

- Web bundles, source maps, service workers, and API Explorer UIs.
- Mobile APK/IPA packages and historical app versions.
- Browser traffic from normal product usage.
- Certificate Transparency, known product subdomains, and generated API hostnames.
- Client configuration files and feature-flag payloads.

Capture for each observed request:

```text
host
method/path
content-type and alt/format controls
client identifier: API key, package name, app signature, project number, origin/referer
user credential type: anonymous, cookie/FPA, OAuth bearer, service account, tenant token
status code and structured error body
```

Brutecat's AI-assisted work is strongest because it first built a corpus: many API keys, many API domains, and many discovery documents. Do the same before fuzzing. A single failing endpoint is noise; a classified matrix of key × API × origin × credential is a map.

## 2. Normalize auth and client-context gates

Large first-party estates often check several gates before business logic. Classify where the request dies.

Common rejection classes:

- Unknown or expired key.
- Key valid but API not enabled for that project/client.
- Browser origin or referer restriction failed.
- Android/iOS package or signature restriction failed.
- User credential missing or wrong type.
- API key project and bearer-token project mismatch.
- Missing OAuth scope, IAM permission, tenant role, feature flag, or label.
- Method blocked by product-specific policy after reaching backend logic.

Turn errors into a routing table:

```text
candidate API host
  -> key/project accepted? yes/no
  -> origin accepted? yes/no + allowed origin guess
  -> credential type accepted? anonymous/cookie/bearer/service
  -> method reached? yes/no
  -> backend method or service name leaked?
  -> next lowest-risk probe
```

Do not skip this step. It prevents blind fuzzing and gives you evidence that a finding crosses a real authorization boundary.

## 3. Mine discovery docs, labels, and generated schemas

Look for every machine-readable schema surface:

- `/$discovery/rest`, OpenAPI JSON, Swagger UI assets, GraphQL introspection, SDK metadata, protobuf descriptors, generated TypeScript/Java/Kotlin clients, and source maps.
- Staging or sandbox API hosts that expose comments or internal-only method names.
- Label, feature, tenant, or client parameters that expand hidden methods.
- Method-override or format controls that route around frontend rules while still staying inside authorized scope.

Operator heuristics:

- Compare unauthenticated, API-key, cookie, and mobile-context schema results.
- Diff schema size and method lists with and without candidate labels or feature flags.
- Preserve schema snapshots with timestamp, key/project context, and accepted origin.
- Treat comments, enum names, and internal documentation links as recon leads, not as proof of impact.

## 4. Recover request shapes from typed-error behavior

Brutecat repeatedly used structured errors to infer unknown request bodies. The general pattern applies to any typed RPC gateway, not only Google.

Safe workflow:

1. Start with a known endpoint and send a deliberately wrong type for one controlled field.
2. Record whether the error names the expected field, type, package, service, or method.
3. If the API supports an array or binary representation such as ProtoJson/protobuf, test in a lab account whether positional wrong-type values reveal adjacent fields.
4. Generate a candidate `.proto`/schema only from error output and public client artifacts.
5. Validate by sending benign read-only requests first.

Look for content types and gateways that often expose this class of signal:

```text
application/json+protobuf
application/x-protobuf
application/grpc-web+proto
application/json with google.rpc.BadRequest details
GraphQL validation errors
OpenAPI/JSON-schema validation errors
```

Report only when the leaked shape enables a concrete, authorized authorization bypass, data exposure, or state transition. A schema leak by itself is usually a recon finding unless it exposes sensitive comments or hidden parameters with impact.

## 5. Decode opaque client parameters

Many product clients carry object IDs inside nested base64, URL-escaped protobuf, or serialized JSON blobs. Brutecat's YouTube work shows why decoding matters: a UI context-menu parameter contained the target account identifier needed for a later cross-product pivot.

Triage steps:

- Identify request parameters that are stable across sessions except for one visible UI object.
- Decode layers: URL encoding, base64/base64url, gzip, protobuf, JSON, or nested encodings.
- Use `protoc --decode_raw` or equivalent only on captured traffic you are authorized to inspect.
- Change only one owned resource ID at a time and observe whether the server recomputes downstream privileged parameters.
- Check whether decoded identifiers are product-local or global account/tenant identifiers.

High-signal pivots:

- Channel ID → global account ID.
- Tenant-visible object ID → backend owner ID.
- Workflow ID → execution queue/task ID.
- Content-owner or billing object ID → contact, entitlement, or admin metadata.
- Debug request ID → internal method, queue, or RPC target.

## 6. Search cross-product resolver paths

A global identifier is dangerous when another product resolves it into sensitive data. Brutecat found this in old/low-traffic product surfaces: YouTube leaked an obfuscated Gaia ID, and Pixel Recorder acted as an email resolver; YouTube Studio leaked an IVP Content Owner ID, and the Content ID API revealed a conflict notification email.

Use this as a general bug-hunting workflow:

1. Build a list of identifiers a scoped product exposes.
2. Classify whether each identifier is local, tenant-scoped, or global.
3. Search other first-party products for APIs that accept the same identifier type.
4. Prefer forgotten, legacy, or niche products, because they often predate newer privacy boundaries.
5. Test only with controlled accounts unless the program explicitly authorizes third-party PII validation.
6. Stop at proof that a controlled identifier resolves across a boundary.

Evidence to capture:

```text
source product + endpoint leaking identifier
identifier type and why it should be product-local
resolver product + endpoint accepting identifier
returned sensitive field on owned test account
why normal UI permissions should not allow this join
```

## 7. Model anti-abuse and recovery oracles safely

The phone-number article is an abuse-boundary lesson, not a license to brute-force users. Identity-recovery flows are high-risk because they often combine partial hints, account existence oracles, display-name checks, phone/email masks, and anti-automation tokens.

Authorized review checklist:

- Does the flow give different status, redirect, timing, or challenge behavior for valid vs invalid identity pairs?
- Are no-JavaScript and JavaScript paths enforcing the same anti-abuse tokens and rate limits?
- Are rate limits keyed on IP only, or also on account, candidate identifier, session, token, ASN, IPv6 prefix, and device fingerprint?
- Can partial hints from one flow be joined with another product's display-name or contact leak?
- Does server-side validation prune impossible candidates, or does the client do most of the filtering?
- Are false positives filtered safely in the proof using owned test identities?

Keep proofs bounded: one or two owned accounts, no broad candidate generation, no bypassing CAPTCHA or anti-abuse on real users.

## 8. Trace workflow/task APIs to internal execution boundaries

The StubZero article shows an escalation pattern common to cloud consoles and automation platforms:

```text
debug/schema endpoint
  -> internal proto/request-response definition
  -> workflow/task editor method
  -> task type capable of backend RPC or code execution
  -> publish/execute boundary
  -> internal service identity or production execution context
```

For authorized cloud-console testing:

- Look for debug endpoints that return proto definitions, workflow queues, task type registries, task icons, or execution metadata.
- Test `alt=proto`, `alt=json`, base64-response headers, and other documented format toggles on owned resources.
- Map create/edit/publish/execute permission boundaries separately. A draft-write issue is lower impact unless publish or execution can be reached.
- Identify the identity used at each hop: end-user, tenant service account, frontend service, workflow runner, internal RPC peer, or production task identity.
- Treat internal RPC primitives as capability-constrained: prove the allowed method/resource boundary instead of claiming universal production access.

High-quality reports include the exact task type, workflow state, permission that should have blocked it, and a controlled command or read on an owned project.

## 9. Use AI as a classifier, not an autopwner

Brutecat's AI work succeeded because the model was wrapped in a disciplined harness. Reuse that pattern:

- Give the model discovery docs, schema snippets, method names, and sampled errors.
- Ask it to classify endpoint purpose, required resource prerequisites, and likely safe probes.
- Force structured output: endpoint group, required IDs, auth context, read/write risk, candidate impact, and confidence.
- Run generated probes only through a controller that enforces scope, rate, HTTP method policy, and stop conditions.
- Feed standard errors back into the classifier so it learns the gate that rejected the call.
- Keep humans in the loop for state-changing endpoints, PII, billing, account recovery, and production execution paths.

A useful prompt frame:

```text
You are classifying an API method for authorized testing.
Return: purpose, required resource IDs, safest read-only probe, auth/client context needed, likely authorization boundary, and reasons not to test automatically.
Do not invent IDs. Do not propose PII enumeration or state changes.
```

## 10. Reporting rubric

A report is ready when it has a narrow source-to-sink chain:

```text
client-context or schema artifact
  -> reachable API method
  -> hidden parameter / identifier / task type / auth context
  -> authorization or privacy boundary crossed
  -> controlled proof on owned resource
  -> clear impact without broad exploitation
```

Include:

- Source article-inspired technique used, without implying the target is Google unless it is.
- Exact host/path/method/content type and credential class.
- Schema, error, decoded parameter, or discovery-doc evidence.
- Scope controls and accounts/resources used for proof.
- What you intentionally did not do: no third-party PII enumeration, no anti-abuse bypass at scale, no destructive task execution, no secret exfiltration.

## Durable lessons

- API keys and mobile/web client contexts are capability hints. Build a matrix of what each context can reach.
- Error messages are an API map. Standardize them before fuzzing.
- Typed gateways leak schemas when wrong-type inputs are reflected with field names or package names.
- Opaque protobuf/base64 UI parameters often carry global identifiers that product teams forgot to threat-model.
- The strongest bugs are cross-product joins: identifier leak in one product, resolver or privileged action in another.
- AI can scale discovery-doc triage, but the harness must enforce scope, rate, and no-PII/no-state-change rules.
