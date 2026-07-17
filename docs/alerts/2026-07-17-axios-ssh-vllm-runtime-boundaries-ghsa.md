# Axios proxy, SSH constraint, and vLLM runtime-channel boundary checks

Sources: hourly offensive-security scan, 2026-07-17 GitHub Security Advisory feeds. Primary entries: [GHSA-pjwm-pj3p-43mv](https://github.com/advisories/GHSA-pjwm-pj3p-43mv), [GHSA-45gg-vh54-h5m9](https://github.com/advisories/GHSA-45gg-vh54-h5m9), [GHSA-f5wc-c3c7-36mc](https://github.com/advisories/GHSA-f5wc-c3c7-36mc), [GHSA-5cgq-3rg8-m6cv](https://github.com/advisories/GHSA-5cgq-3rg8-m6cv), [GHSA-x527-x647-q7gg](https://github.com/advisories/GHSA-x527-x647-q7gg), [GHSA-hjq4-87xh-g4fv](https://github.com/advisories/GHSA-hjq4-87xh-g4fv), [GHSA-9pcc-gvx5-r5wm](https://github.com/advisories/GHSA-9pcc-gvx5-r5wm), [GHSA-9f8f-2vmf-885j](https://github.com/advisories/GHSA-9f8f-2vmf-885j), [GHSA-mrw7-hf4f-83pf](https://github.com/advisories/GHSA-mrw7-hf4f-83pf), [GHSA-94f4-hr76-p5j6](https://github.com/advisories/GHSA-94f4-hr76-p5j6), and [GHSA-6c4r-fmh3-7rh8](https://github.com/advisories/GHSA-6c4r-fmh3-7rh8). Nearby vLLM DoS-only entries ([GHSA-v82g-2437-67m2](https://github.com/advisories/GHSA-v82g-2437-67m2), [GHSA-rwxx-mrjm-wc2m](https://github.com/advisories/GHSA-rwxx-mrjm-wc2m), and [GHSA-8wr5-jm2h-8r4f](https://github.com/advisories/GHSA-8wr5-jm2h-8r4f)) are tracked here only as scope context, not standalone exploit-path guidance.

This batch is durable for operators because the advisories expose reusable boundary classes: URL canonicalization before proxy/no-proxy routing, SSH certificate and agent constraints dropped across multi-step authentication or key forwarding, AI inference runtime channels that deserialize or broadcast data on unintended network interfaces, ASGI `Host` header parsing drift before API-key checks, and audio preprocessing differentials where the content humans hear is not the signal an AI model receives.

!!! warning "Authorized validation only"
    Keep proofs to fake proxy logs, disposable SSH certificates and agents, lab vLLM clusters, synthetic prompt embeddings, marker-only callbacks, non-sensitive runtime state, malformed `Host` header decision tables, and short synthetic audio canaries. Do not query cloud metadata, capture real bastion keys, forward production agents, deserialize hostile payloads against production inference workers, bypass production model APIs, collect prompts or transcripts, or publish weaponized tensors/pickle payloads.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-pjwm-pj3p-43mv](https://github.com/advisories/GHSA-pjwm-pj3p-43mv) | Axios `<=0.31.1` and `>=1.15.0,<1.16.0` | `NO_PROXY` entries such as `127.0.0.1` or `169.254.169.254` are compared before IPv4-mapped IPv6 canonicalization | Test SSRF/client-proxy controls where internal IPv4 destinations can be expressed as `[::ffff:...]` and routed through a proxy unexpectedly. |
| [GHSA-45gg-vh54-h5m9](https://github.com/advisories/GHSA-45gg-vh54-h5m9) | `golang.org/x/crypto/ssh` before `0.52.0` | `PartialSuccessError` with permissions could discard certificate restrictions after a second factor | Validate SSH servers that combine certificate auth with keyboard-interactive or other second-factor callbacks. |
| [GHSA-f5wc-c3c7-36mc](https://github.com/advisories/GHSA-f5wc-c3c7-36mc) | `golang.org/x/crypto/ssh/agent` before `0.52.0` | Remote-agent constraint extensions such as destination restrictions were not serialized when keys were forwarded | Test whether forwarded canary keys lose intended `restrict-destination` semantics. |
| [GHSA-5cgq-3rg8-m6cv](https://github.com/advisories/GHSA-5cgq-3rg8-m6cv) | `golang.org/x/crypto/ssh` before `0.52.0` | Revoked CA signature keys were not enforced consistently | Add negative controls for `@revoked` CA/signature-key material when certificate trust anchors are tested. |
| [GHSA-x527-x647-q7gg](https://github.com/advisories/GHSA-x527-x647-q7gg) | `golang.org/x/crypto/ssh` before `0.52.0` | `VerifiedPublicKeyCallback`-style permission checks could skip source-address validation in callback compositions | Check callback composition, not only individual auth methods, when testing SSH certificate principal/source restrictions. |
| [GHSA-hjq4-87xh-g4fv](https://github.com/advisories/GHSA-hjq4-87xh-g4fv) | vLLM `>=0.6.5,<0.8.5` with V0 `PyNcclPipe` KV-cache transfer | CPU-side serialized control messages can reach deserialization on a service intended to be private, while the underlying listener can bind more broadly than expected | Map KV-cache transfer interfaces and prove reachability only with lab canaries. |
| [GHSA-9pcc-gvx5-r5wm](https://github.com/advisories/GHSA-9pcc-gvx5-r5wm) | vLLM `>=0.5.2,<0.10.0` V0 multi-node tensor parallel deployments | Secondary hosts deserialize ZeroMQ messages from the primary-host broadcast path | Validate whether multi-node AI workers expose unauthenticated serialization channels across tenant or network boundaries. |
| [GHSA-9f8f-2vmf-885j](https://github.com/advisories/GHSA-9f8f-2vmf-885j) | vLLM `>=0.5.2,<0.8.5` multi-node deployments | Primary-host ZeroMQ `XPUB` can bind broadly and broadcast internal state to arbitrary clients with network access | Use non-sensitive subscription markers to prove exposure; avoid collecting prompts, tensors, or model internals. |
| [GHSA-mrw7-hf4f-83pf](https://github.com/advisories/GHSA-mrw7-hf4f-83pf) | vLLM `>=0.10.2,<0.11.1` Completions API with user-supplied prompt embeddings | Sparse tensor deserialization through `torch.load(..., weights_only=True)` can cross into memory-corruption behavior | Treat prompt-embedding upload as a binary parser boundary and validate only in isolated harnesses. |
| [GHSA-94f4-hr76-p5j6](https://github.com/advisories/GHSA-94f4-hr76-p5j6) | vLLM `>=0.3.0,<0.22.0` OpenAI-compatible API when directly exposed by ASGI/uvicorn-style servers | API-key middleware derives `url_path` from Starlette URL reconstruction, while routing uses the raw HTTP path; special characters in `Host` can make the middleware see a non-`/v1` path while the router still reaches `/v1` | Test direct vLLM API exposure for `Host` parser differentials with fake API keys and harmless model-list routes. |
| [GHSA-6c4r-fmh3-7rh8](https://github.com/advisories/GHSA-6c4r-fmh3-7rh8) | vLLM `>=0.5.5,<0.18.0` audio-model preprocessing via Librosa-style mono downmixing | Multi-channel audio can be averaged differently than human playback expectations, letting LFE/extra channels affect model input while normal front channels sound benign | Validate moderation, transcription, or voice-auth assumptions with owned synthetic audio fixtures and compare human-playback, reference downmix, and model transcript/effect. |

## Replayable validation boundaries

### Axios `NO_PROXY` IPv4-mapped IPv6 checks

1. Build a local harness with an Axios version in scope, a configured HTTP proxy you control, and `NO_PROXY` entries for internal IPv4 canaries such as `127.0.0.1` or a documentation-range lab address.
2. Start an owned HTTP canary on the destination and a fake proxy that logs only method, host, and path.
3. Compare three request forms:
   - canonical IPv4 URL expected to bypass the proxy;
   - bracketed IPv4-mapped IPv6 URL for the same host;
   - patched Axios or a hardened proxy policy as the negative control.
4. Evidence should show whether the IPv4-mapped form routes through the proxy even though the same underlying destination is intended to be covered by `NO_PROXY`.
5. Do not use cloud metadata or internal production admin hosts as proof targets. If a customer wants metadata validation, use a metadata-simulator endpoint under their written scope.

Report this as **URL host canonicalization mismatch -> `NO_PROXY` decision -> proxy-mediated access to an internal IPv4 destination**. Include Axios version, proxy environment variables, parsed host forms, and proxy/canary logs.

### Go SSH certificate and agent-constraint checks

1. Use a disposable SSH server built on `golang.org/x/crypto/ssh`, disposable client keys, and an isolated agent. Never forward a real operator agent into the harness.
2. Create canary certificates with explicit restrictions: source-address, force-command, principals, and a revoked CA/signature-key control where relevant.
3. Exercise the authentication composition used by the target, especially public-key plus keyboard-interactive or other flows that can return partial success.
4. For agent forwarding, add a key with a destination-restriction extension and confirm whether the remote agent view preserves or silently drops that constraint.
5. Record accept/deny decisions only. Avoid opening a real shell, touching bastions, or proving impact with production commands.

Report this as **SSH auth callback or agent-forwarding serialization -> certificate/agent restriction dropped -> canary login or key-use decision differs from policy**. Strong evidence is a decision table with vulnerable, fixed, and policy-negative controls.

### vLLM runtime-channel and prompt-embedding checks

1. Restrict testing to isolated vLLM labs or explicitly approved AI infrastructure. Prefer a two-node lab with fake prompts and a tiny disposable model.
2. Inventory runtime channels before sending payloads: V0 versus V1 engine, tensor parallelism across hosts, `PyNcclPipe` KV-cache transfer, ZeroMQ ports, `TCPStore` bind addresses, and Completions API prompt-embedding upload paths.
3. For `PyNcclPipe` and ZeroMQ, first prove network reachability with socket banners, connection outcomes, or harmless subscription markers. Do not send weaponized pickle payloads outside a lab.
4. For ZeroMQ broadcast exposure, subscribe with a lab client and capture only synthetic marker traffic generated by the test harness. Do not collect live prompts, hidden states, tensors, or tenant data.
5. For prompt embeddings, use a standalone harness or disposable worker with synthetic sparse tensors designed to exercise validation decisions, not a production inference endpoint. Preserve crash/memory evidence locally and avoid publishing binary payloads.
6. Repeat against patched versions or V1/non-multi-node configurations as negative controls.

Report this as **AI worker runtime channel -> unauthenticated network reachability -> deserialization or internal-state exposure**, or **Completions prompt-embedding upload -> tensor parser boundary -> controlled crash/memory-safety evidence in lab**.

### vLLM OpenAI API-key middleware parser checks

1. Only test vLLM endpoints you own or where the customer explicitly approved direct API-gateway validation. Do not attempt to bypass production API keys to access real models or prompts.
2. Build a local or customer-provided lab with an affected vLLM version, an OpenAI-compatible route such as `/v1/models`, and a configured `VLLM_API_KEY`/`--api-key`.
3. Send four decision-table requests:
   - normal `/v1/...` without `Authorization` expected to return `401`;
   - normal `/v1/...` with a fake/wrong key expected to return `401`;
   - normal `/v1/...` with the lab key expected to return success;
   - malformed `Host` variants containing URL special characters such as `/` or `?`, without a valid key, expected to demonstrate whether middleware path reconstruction differs from router path selection.
4. Repeat through an RFC-conforming reverse proxy such as nginx as a negative control when that matches the target architecture; the advisory notes proxy-fronted deployments may not be affected.
5. Evidence should be status codes, request-line/Host/path parsing, and harmless route results only. Do not run inference, enumerate private models beyond a synthetic lab fixture, or collect prompts.

Report this as **ASGI Host header URL reconstruction -> API-key middleware path check -> OpenAI route reached without expected authorization**. Include the vLLM version, ASGI server, direct-vs-proxied topology, exact redacted request bytes, and negative controls.

### vLLM audio preprocessing differential checks

1. Scope this to audio-enabled vLLM labs, moderation sandboxes, or voice-auth test tenants using synthetic voices and synthetic content. Never use real user recordings or biometric enrollment material.
2. Create short multi-channel fixtures with:
   - benign front left/right channels;
   - a controlled marker or interference signal in LFE, rear, overhead, or otherwise unsupported/extra channels;
   - a stereo-only negative control containing the same benign front-channel content.
3. Compare three views of each fixture:
   - what normal playback surfaces to a human tester on common speakers/headphones;
   - a reference downmix that follows the target policy or ITU-style weighting expected by the assessment;
   - the vLLM/audio-model preprocessing and resulting transcript, moderation label, or voice-auth decision.
4. Keep markers harmless: use synthetic words, tones, or nonsense tokens. Do not hide real abusive content, authentication phrases, payment instructions, or social-engineering audio.
5. A strong proof shows a policy-relevant mismatch: the human/reviewer path appears benign while the model path receives or misses the controlled marker due to channel handling.

Report this as **multi-channel audio fixture -> downmix/preprocessing differential -> model-visible content differs from human-visible content**. Include the audio channel layout, fixture hash, preprocessing library/path, transcript/label decision table, and stereo/patched/reference controls.

## Operator checklist

- [ ] Did the proof use owned canary infrastructure rather than metadata/internal production hosts?
- [ ] Are URL host forms, proxy decisions, and destination equivalence shown side by side?
- [ ] Are SSH certificate restrictions and agent constraints represented as explicit allow/deny decision tables?
- [ ] Is the vLLM deployment actually using the affected engine/channel/API path, rather than only a vulnerable package version?
- [ ] For vLLM API-key checks, is the deployment directly exposed to the ASGI server path, or is a standards-compliant reverse proxy normalizing `Host` first?
- [ ] For audio checks, did the report compare human playback, reference downmix, and model-visible transcript/decision using synthetic fixtures only?
- [ ] Are all payloads inert, non-sensitive, and reproducible in a lab?

## Reporting notes

- Lead with the trust boundary that failed: URL canonicalization, SSH restriction propagation, AI runtime-channel isolation, ASGI path reconstruction before API-key enforcement, or audio channel preprocessing before model trust.
- Separate reachability from code execution. For vLLM, a high-quality report first proves the unintended channel is exposed, then uses lab-only markers to show the parser or broadcast effect.
- Redact proxy credentials, SSH key material, tokens, model names, cluster hostnames, and any customer topology that is not necessary to reproduce the decision boundary.
