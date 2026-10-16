---
title: SGLang inference API and model-runtime boundaries
---

# SGLang inference API and model-runtime boundaries

A July 30 advisory wave exposes a reusable AI-inference review pattern: optional subsystems and model-management routes can bypass the authentication, safe-loading, network, and data-release assumptions applied to ordinary generation requests.

Sources:

- [GHSA-96j3-rjf9-2hxp](https://github.com/advisories/GHSA-96j3-rjf9-2hxp): enabling the optional dumper server can expose an inference-request-to-code-execution boundary;
- [GHSA-vwmc-327h-6x3j](https://github.com/advisories/GHSA-vwmc-327h-6x3j): `/server_info` can return API-key and TLS-keyfile configuration when only the admin API key is configured;
- [GHSA-r344-357p-w9pp](https://github.com/advisories/GHSA-r344-357p-w9pp): `/update_weights_from_disk` can fall back to `torch.load(..., weights_only=False)` for repository `.bin` files;
- [GHSA-x6x2-r266-cx9p](https://github.com/advisories/GHSA-x6x2-r266-cx9p): unauthenticated distributed-weight broadcast and transfer routes can release model weights when API keys are unset;
- [GHSA-359v-m36h-r94v](https://github.com/advisories/GHSA-359v-m36h-r94v): `/load_lora_adapter_from_tensors` can cross an incomplete `SafeUnpickler` denylist into object reconstruction with execution impact; and
- [GHSA-hg26-hr8r-fxc9](https://github.com/advisories/GHSA-hg26-hr8r-fxc9): multimodal `image_url` handling can reach server-side URLs and local files.

!!! warning "Disposable inference labs only"
    Use a toy model, fake API keys, synthetic weight tensors, owned HTTP listeners, and temporary files. Never load an untrusted pickle, collect real model weights, request cloud metadata, read credentials, or exercise production inference workers.

## Boundary matrix

| Surface | Preconditions to confirm | Bounded positive |
| --- | --- | --- |
| dumper subsystem | `DUMPER_SERVER_PORT` is set and the route is reachable from an inference request | an instrumented dumper callback receives a fixed in-memory marker |
| `/server_info` | admin API key configured; ordinary API authentication state recorded separately | response contains only a planted fake secret field or synthetic keyfile path |
| weight update | caller can select repository/path and `.bin` loader fallback is reachable | loader recorder reports an attempted unsafe-load mode for a synthetic artifact |
| distributed weights | broadcast/transfer endpoints reachable while API keys are unset | a one-tensor toy-model hash crosses to a disposable receiver |
| LoRA tensor adapter | caller-supplied serialized tensor object reaches the unpickler | patched recorder observes a denied synthetic class reference; no constructor runs |
| multimodal URL | `image_url` is fetched by the server | owned listener receives the canary, or a temporary synthetic file marker is returned |

Treat route reachability, authentication, parser/loader selection, side effect, and impact as separate edges. A route that returns 200 is not proof of weight disclosure or execution.

## Route and authentication inventory

1. Deploy the exact SGLang build with a toy model, no cloud role, no production network route, and no mounted credentials.
2. Enumerate ordinary generation, admin, model-update, adapter, dumper, distributed-worker, and information routes from the running route table and startup flags.
3. For every route, test no credential, malformed credential, ordinary API key, admin API key, and an unrelated key. Record which middleware actually ran, not merely what the route documentation claims.
4. Repeat with API keys unset, only the ordinary key set, only the admin key set, and both set. Optional startup flags can change both route registration and policy coverage.
5. Preserve a decision table containing route, method, feature flag, actor, status, handler, and synthetic effect.

## Safe loader and object-reconstruction checks

1. Replace `torch.load`, pickle reconstruction, and LoRA tensor-deserialization entry points with recorders in a test build. Record artifact type, selected loader, `weights_only` value, referenced class names, and whether any fallback occurred; the recorder must refuse to instantiate objects.
2. Use an owned repository containing ordinary safe tensors, a malformed `.bin`, and a metadata-only fixture that requests a nonexistent synthetic class. Do not include executable reducers or callbacks.
3. Exercise startup loading and runtime weight-update routes independently. A safe startup path does not prove the update route uses the same loader policy.
4. For LoRA, compare allowlisted tensor primitives, unknown globals, nested containers, extension opcodes, and a corrected allowlist. An incomplete denylist is proven by a forbidden class reference reaching the reconstruction decision, not by executing it.
5. A strong bounded positive is **caller-selected artifact -> unsafe fallback or unapproved global reaches the recorder -> corrected build rejects the same fixture**.

## Distributed-weight and information-release checks

- Use a toy model with one random tensor and record its hash before testing. Configure a disposable receiver that can accept only that expected byte count and cannot forward data.
- Exercise broadcast initiation, receiver registration, and transfer independently under every authentication state. Stop after the toy tensor hash is observed.
- Plant fake API-key text and a synthetic TLS path before requesting `/server_info`; redact even fake values in published evidence and report field names plus hashes.
- Do not infer real-model exfiltration from route reachability. Record sender, receiver, authentication middleware, tensor identity, byte count, and exact caller-controlled selector.

## Multimodal fetch boundary

1. Operate an owned HTTP image endpoint and a second owned redirect endpoint. Also create one temporary local image canary containing a random marker.
2. Submit ordinary owned HTTPS, redirect, userinfo, encoded-host, alternate-address, and local-file-shaped values one dimension at a time. The lab must have no route to metadata or production internal services.
3. Record raw value, parsed scheme/authority/path, DNS result, connected peer, redirect chain, file-open attempt, and whether image bytes reached preprocessing.
4. Report callback receipt and local-file opening separately. A validator acceptance or parser error is not final-destination proof.

## September 22 follow-up: diffusion-orchestrator ZeroMQ pickle RCE, and the NeMo sibling pack

Two advisories extend this page's axes to the disaggregated-diffusion path and to the adjacent NeMo stack:

- **SGLang multimodal/diffusion runtime: unauthenticated RCE via unauthenticated ZeroMQ ROUTER socket** ([GHSA-xv76-mrpv-26pg / CVE-2026-93088](https://github.com/advisories/GHSA-xv76-mrpv-26pg)). The disaggregated-diffusion orchestrator's `DiffusionServer` binds an **unauthenticated ZeroMQ ROUTER socket to a network interface** and hands the final frame of each multipart message straight to `pickle.loads()` **before any validation**. Durable rules this reinforces: (1) inventory the *side-channel* listeners (ZMQ/IPC/ROUTER/REP ports, worker heartbeats, orchestrator control channels) separately from the HTTP API — they frequently ship with **no authN at all** because "it's internal", while binding `0.0.0.0`; scan them like public API surface once reachable. (2) Any message frame reaching `pickle.loads()` is code execution, so the audit question is what deserializes *before* the first `if` — "validation later" is validation never. (3) This is the same shape as the July dumper-server finding: optional/orchestration subsystems carry the weakest trust assumptions in inference stacks.
- **NVIDIA NeMo dataset-loading and tokenizer pack** ([GHSA-mmmc-pj37-37jg / CVE-2026-65178](https://github.com/advisories/GHSA-mmmc-pj37-37jg): a crafted `model_config.yaml` injects unsafe parameters into the dataset-loading workflow; [GHSA-4v72-rpj8-4xq7 / CVE-2026-65179](https://github.com/advisories/GHSA-4v72-rpj8-4xq7): `TabularTokenizer` deserializes an attacker-controlled `.pkl` via unvalidated `pickle.load()`). Durable rule: on any ML platform, **config files are an input surface, not just data** — every YAML/env entry that reaches a loader's parameter namespace gets the same unsafe-parameter sweep as user data (this is the same axis as the Aug 5 LMDeploy `--extra-config` argv leg on the command-wrapper page). `.pkl` artifacts remain the deserialization sink: test loader selection between `weights_only=True`/safe and legacy paths per code path, as already prescribed above.

Bounded proof stays per this page's existing discipline: owned listeners, synthetic frames refused by a recording unpickler (no reducer execution), fake config canaries in disposable workspaces, patched-build negative controls. Never bind test orchestrators on routable interfaces.

## September 23 follow-up: LMDeploy vision-language image-URL SSRF (CVE-2026-33626)

- **LMDeploy <0.12.3 SSRF via `load_image()`** ([GHSA-6w67-hwm5-92mq / CVE-2026-33626](https://github.com/advisories/GHSA-6w67-hwm5-92mq)): `lmdeploy/vl/utils.py` `load_image()` (and `encode_image_base64()`) `requests.get()` any `http`-prefixed `image_url` from a normal `/v1/chat/completions` multimodal request with **no IP/scheme validation before the fetch** — cloud metadata (169.254.169.254), RFC-1918, loopback all reachable. Amplifier pair that is the real finding: the API server **binds `0.0.0.0` by default and API keys are disabled by default**, so the fetch primitive is unauthenticated by default posture. Durable rules for this page's multimodal-fetch section: (1) every multimodal content field (`image_url`, `audio_url`, file references) in OpenAI-compatible servers is an SSRF leg *inside an otherwise-authenticated-looking API* — test it as a separate input from the text prompt; (2) check the **server's own default posture** (bind address, auth-on-by-default?) before scoring — same code, different defaults, unauthenticated-vs-authenticated severity delta; (3) inference stacks keep re-growing this leg per modality (this page's original multimodal-fetch item, AgentScope April, Mealie fold Aug 5) — when auditing a new VL/audio model server, `load_image`-shaped fetch helpers are the first grep. Validation stays per the existing multimodal-fetch workflow: owned HTTP image endpoint + owned redirector, one dimension at a time, final-destination socket proof, never metadata or production internals.

## Evidence and reporting

Name only the boundary actually proven: **optional subsystem to unguarded handler**, **admin-key configuration to information-route policy drift**, **runtime model selector to unsafe loader fallback**, **serialized adapter to unapproved object reconstruction**, **unauthenticated transfer route to toy-weight release**, or **multimodal URL to server fetch/local file open**. Include exact startup flags, authentication matrix, route table, recorder traces, synthetic hashes, and corrected-build controls.

## October 8 15:3xZ follow-up: ZMQ decoder `pickle.loads` survives the msgpack "safe" path — config-flag flip does not disable the gadget (CVE-2026-93034 / [GHSA-w4hv-c72g-pqx6](https://github.com/advisories/GHSA-w4hv-c72g-pqx6))

SGLang's own product now carries the wrapper-gadget leg: the ZMQ message decoder **unconditionally `pickle.loads` any `PickleWrapper` payload in `_maybe_unwrap_pickle`** — no type allowlist, no authentication — and critically the gadget **still fires on the msgpack path even with `SGLANG_USE_PICKLE_IPC` disabled**: the wrapper class exists specifically to smuggle pickle inside the "safe" serializer, so the operator-visible safe-mode flag only changes the envelope, not the trust decision. Remote exploitability arrives via data-parallel attention with a non-loopback `--dist-init-addr` (the same operator-flag-widens-bind axis as LMCache's `--host` on the Oct 2 transport page).

Rules: (1) **audit the unwrap/extension hook, not the serializer name** — msgpack/cbor ext-type and wrapper-class handlers that dispatch to `pickle.loads`/`yaml.unsafe_load`/`torch.load` are RCE regardless of which format the config says is active; this is the third instance across these wiki pages (LMCache ext-code-1 Oct 7, SGLang diffusion-orchestrator pickle Sept 22 on this page, now SGLang core wrapper) — treat "ZMQ + msgpack + Python" as a standing pre-auth RCE fingerprint on AI infra; grep `_maybe_unwrap`/`ExtType`/`default=` near deserializers first. (2) **A security-relevant env flag is only a mitigation if the dangerous sink is gated by it at the call site** — verify by running with the flag off and sending the wrapper frame anyway (lab peer, inert canary), never against shared clusters.

## October 16 follow-up: dumper filter expression is an `eval()` sink; `__globals__` walk escapes the "sandbox" — code exec in the scheduler deferred to the next forward pass (CVE-2026-111391 / [GHSA-vfgj-p7f7-r3v8](https://github.com/advisories/GHSA-vfgj-p7f7-r3v8), critical, SGLang 0.5.10–0.5.22)

The July dumper leg on this page now has its concrete mechanism: `_evaluate_filter()` runs the caller-supplied dumper filter expression through `eval()`, and the "sandbox" is escaped by walking a live function object's `__globals__` (`re.search.__globals__` → module namespace → `__builtins__`) — the classic Python sandbox-walk chain: any reachable live object with a code reference (`__class__.__mro__`, `__subclasses__`, frame/traceback objects, or `func.__globals__` of an already-imported module) reopens full builtins no matter which name set `eval(expr, {"__builtins__": {}}, ...)` hands it. Durable rules:

1. **Filter/expression/rule parameters are `eval` candidates, not string configs.** Any admin- or feature-endpoint that accepts a "filter", "expression", "condition", or "matcher" string on an inference/AI serving stack should get the expression-evaluation probe (`1+1`, `__import__`, `re.search('a','a').__globals__`) before you waste time treating it as data. Grep for `eval(` / `literal_eval(` / `Template(` / `compile(` near the handler; `eval` with an emptied `__builtins__` dict is *not* a sandbox — the escape only needs one live object reachable from the locals/globals you were handed.
2. **Same endpoint, second leg — re-sweep the dumper surface.** GHSA-96j3-rjf9-2hxp (July) flagged the dumper route as a boundary; this October advisory detonates the filter expression inside it. When a page already names a route as "suspicious boundary," every parameter *on that route* gets a fresh battery post-disclosure rather than closing the finding at route level.
3. **Detonation timing is a separate axis from acceptance.** The injected code executes in the **scheduler process on the next forward pass**, not at request time — a 200 at `/dumper/configure` plus an inert-looking response proves nothing; schedule a benign canary with a side effect you can observe later (marker file, owned callback fired on next inference call). Deferred sinks hide from synchronous request/response testing and put the payload into a standing state that survives the attacker disconnecting.
4. **Feature-flag reachability still gates the surface:** the endpoint is unauthenticated but only live when `DUMPER_SERVER_PORT` is set — same optional-subsystem fingerprint rule as this page's route inventory section; probe the flag-gated route family's full parameter set, not just its existence.

Bounded proof stays per this page's discipline: lab scheduler, toy model, inert marker expression (write a random token to a temp path or hit an owned listener), no shared inference workers, never persistence or lateral steps.

## October 16 follow-up: caller-supplied `mm_hashes` is the prefix-cache key — cross-request KV poisoning and image disclosure (CVE-2026-111392 / [GHSA-fgff-m398-2gh5](https://github.com/advisories/GHSA-fgff-m398-2gh5), SGLang through 0.5.21, no fixed version at publication)

Multimodal requests carry `mm_hashes` and the server **trusts the caller-supplied value verbatim as the multimodal prefix-cache key** — the cache never re-derives the digest from the image bytes actually sent. An attacker who learns or predicts another request's hash (values leak in logs, debug endpoints, metrics labels, and predictable forms like URL/filename digests) can send a *different* image under that hash via `/generate` and either **poison the cached KV entry so victims' later requests are conditioned on attacker content** or **read out the response shape/latency of a cached entry belonging to someone else's image**. Durable rules:

1. **A cache key chosen by the request is a shared writable namespace.** The audit question for any serving stack with prefix/KV/response caching: is the key a digest *the server computed from the served content*, or a label *the client supplied*? Client-selectable keys = poisoning + cross-tenant read surface regardless of auth model. Grep the request schema for hash/checksum/id fields that skip content verification (`hash` accepted alongside `image_data` with no `sha256(image_bytes) == hash` check is the fingerprint).
2. **Cache-hit behavior is itself the oracle.** Timing deltas (hit skips image preprocessing), deterministic output repetition, and cached-token counts in usage fields distinguish hit/miss without any explicit disclosure route — probe with your own two-user lab: request A under a fresh hash, request B different bytes same hash, measure.
3. **Prediction matters twice:** if hashes are derived client-side from predictable material (image URL, filename, content the attacker can also compute), the attacker doesn't need to observe them at all — enumerate the derivation, then enumerate candidate keys offline.
4. Same page's standing rule reconfirmed: the multimodal path keeps producing the newest SGLang boundary legs (fetch leg, dumper `eval` leg Oct 16, now cache-key leg) — when auditing an inference server, treat every multimodal *metadata* field as first-class attack input, not decoration alongside the prompt.

Bounded proof: two isolated lab clients with synthetic images and random markers, owned canary content only; never replay or probe production cache state or another tenant's traffic.
