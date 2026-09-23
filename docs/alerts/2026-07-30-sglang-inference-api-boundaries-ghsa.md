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
