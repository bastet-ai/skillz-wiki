---
title: Xinference Llama3 tool-call eval() and LLM-output-to-execution boundaries
---

# Xinference Llama3 tool-call `eval()` and LLM-output-to-execution boundaries

A critical GitHub Security Advisory (CVSS 10.0) published 2026-08-21 describes **Xinference** (the `xinference` PyPI package) calling Python's unsafe `eval()` on **Llama3 tool-call output produced by a large language model**. Because that model output is reachable from attacker-controlled prompts sent to the OpenAI-compatible `/v1/chat/completions` endpoint, and the tested default deployment had **no authentication**, a remote unauthenticated attacker can steer the model into emitting a Python expression that the server evaluates during tool-call post-processing. That is **CWE-95 (Eval Injection)** and, in the default deployment, an unauthenticated RCE. Fixed in `xinference` `2.7.0`.

The durable operator pattern: **in any model-serving / agentic system that turns LLM output into a structured result, the moment that result is fed to `eval()`, `exec()`, `ast.literal_eval` with a non-literal, `pickle`, or a shell, the "model output" channel becomes a code-execution channel** — and the prompt is the remote write primitive. This is the same family as agent tool command injection, but the attacker surface is the **model's own output**, not a tool argument.

Source record:

- [GHSA-x2rj-828p-hx9m / CVE-2026-61539](https://github.com/advisories/GHSA-x2rj-828p-hx9m): Xinference RCE via unsafe `eval()` in Llama3 tool-call parsing; unauthenticated via `/v1/chat/completions` in the tested default deployment; patched `2.7.0`; CWE-95.

Confirm the exact `xinference` version, which model backend (Transformers backend in the report) and whether `tools` are enabled on the endpoint, whether authentication is actually enabled (the CVE is unauthenticated *only* because the tested deployment had it off), and whether the `/v1/chat/completions` surface is reachable at all, before testing.

!!! warning "Lab-only, no live RCE, inert sinks, no real model keys"
    Use a disposable Xinference install on an isolated host with a local or mocked model and **no** production LLM/API keys. Patch the post-processing execution sink (`eval`, `exec`, `subprocess`) with a denied recorder that captures the expression and rejects before execution. Never send crafted prompts to an internet-facing Xinference deployment, and never execute a real command to prove the boundary.

## Boundary map

| Surface | Intended authority | Untrusted input | Bounded positive |
| --- | --- | --- | --- |
| `/v1/chat/completions` (restful_api.py) | authenticated model inference | `tools` + attacker-crafted `messages`/prompt | a prompt that makes the model emit a Python expression in a tool-call field |
| `handle_chat_result_non_streaming` (transformers/core.py) | internal result routing | model response with `tools` | post-processing invoked when `tools` present |
| `_post_process_completion` / Llama3 tool parser | parse structured tool-call JSON | model's tool-call output string | parser routes the model string to a Python-evaluable path |
| `eval()` in `llama3_tool_parser.py` | parse a JSON-like tool-call fragment | the raw model output | `eval()` receives a non-literal, attacker-steerable expression |
| auth gate | per-deployment | none (disabled in tested default) | unauthenticated remote reach to the chat endpoint |

The finding is the **broken binding between "model output" and "Python evaluation"**, plus the **authentication precondition** that makes it remote. Capture the prompt, the model tool-call fragment, and the denied-sink record separately.

## 1. Establish the reachability and authentication state

The RCE is only *unauthenticated* because the tested deployment disabled auth. Record both facts:

1. Is `/v1/chat/completions` reachable on the target authority (internet-facing, DMZ, VPN, internal)?
2. Is authentication actually enforced on that route in the deployment being assessed? (The advisory's "unauthenticated" claim is deployment-specific.)
3. Which `xinference` version, and is `tools` enabled for the deployed model?
4. Which model backend (Transformers backend in the report) and which model — the Llama3 tool-call parser is the one named in the CVE.

If auth is enforced, downgrade the finding to **authenticated** RCE / tool-call poisoning, not unauthenticated. The distinction changes the exploit path and the operator's privilege requirements.

## 2. Instrument the post-processing execution sink in a disposable lab

Only when the assessment authorizes exploit-path validation:

1. Clone the affected `xinference` (`< 2.7.0`) into an isolated lab with a local/mock model, no production LLM/API keys, and no outbound network.
2. Patch `eval` / `exec` / `subprocess` on the tool-call post-processing path with a recorder that captures the expression and **denies execution** (throws or returns a fixed inert value).
3. Drive `/v1/chat/completions` with a `tools`-enabled request and a prompt crafted so the model's tool-call output is a Python expression (e.g. `__import__('os').system('...')` or the `execSync`/`child_process` shape if the backend differs). The model does not need to *actually* emit it in a real lab — for the sink proof, you can also feed the parser a recorded tool-call fragment that matches the Llama3 tool-call grammar.
4. Confirm the recorder observed the `eval()` argument on the affected build and **did not** on `2.7.0`.
5. Record the exact parser location (`llama3_tool_parser.py`) and the expression it received.

A bounded positive is **attacker-steered prompt (or recorded tool-call fragment) → Llama3 tool parser → `eval()` invoked with a non-literal, attacker-influenced expression captured by the denied recorder**, on the affected build only. Do not run a real command; the proof is the recorder capture plus the reachability/auth table from section 1.

## 3. Separate "model emitted it" from "sink accepts it"

Two distinct claims, both required for a strong report:

- **Reachability + auth**: an unauthenticated (or appropriately-privileged) remote peer can reach the tool-call post-processing path.
- **Sink**: that path evaluates non-literal Python from model output.

If you only prove the sink in a lab with a fed fragment but cannot show the model can be steered to emit it in the real deployment, report the **sink + the steering precondition** and mark the end-to-end RCE as "requires model to emit attacker-influenced expression under deployment X." If you only reach the endpoint but the deployed model/backend does not use the Llama3 tool parser, the specific CVE path is not present.

## Reporting heuristics

Lead with the crossed channel and the auth state:

- **`/v1/chat/completions` → Llama3 tool-call output → `eval()` on model-emitted Python (CWE-95)**
- **authentication disabled in tested default deployment → remote unauthenticated reach**

Strong reports include the exact `xinference` version, the auth state on the route, the model backend and model, whether `tools` is enabled, the exact parser location, the denied-sink capture (prompt + tool-call fragment + `eval()` argument), and the `2.7.0` negative control. Durable operator lesson for any model-serving or agentic stack: **treat LLM output as untrusted input to any evaluator** — `eval`, `exec`, `ast.literal_eval` on non-literals, `pickle`, YAML load, shell, or template render are all the same boundary. A prompt that controls model output is a write primitive into that evaluator.

## October 18, 2026 follow-up: `model_name` backslash traversal on the registration endpoint (CVE-2026-112051)

A second, independent boundary in the same product landed 2026-10-18: **Xinference through 4.0.1** accepts a custom model registration via `POST /v1/model_registrations/{model_type}` with a `model_name` like `..\..\evil`, and the name is used to build a file path under the model directory — giving an **unauthenticated attacker arbitrary `.json` file write/delete** through the process-writable scope (fix commit `beddc97a`, [GHSA-xhc4-qrhj-p2jj / CVE-2026-112051](https://github.com/advisories/GHSA-xhc4-qrhj-p2jj), VulnCheck writeup).

The fix diff is the whole lesson. Pre-fix, the validator was a single regex denylist:

```python
# pre-fix (utils.py is_valid_model_name)
return re.match(r"^[^+/?%#&=\s]*$", model_name) is not None
```

It denies `/` but **not `\`**, and does not reject bare `.`/`..`. On Windows the backslash is the path separator, so the "safe name" gate is separator-blind on one OS while the filesystem consumer splits on it. Post-fix adds `\` to the deny class plus explicit `.`/`..` rejection.

Durable operator rules:

1. **Separator-parity on every name-as-filename field.** Any identifier that becomes a path segment (model name, workspace, export name, cache key, username-as-dir) must be probed with `/`, `\`, `..`, `.%20`, `...`, and trailing-separator variants — a validator that denies only one separator is an OS-conditional traversal. Deny-list character classes are the fingerprint: grep validators for `[^...]` classes and check which separator is missing.
2. **Registration/persistence endpoints are standing write primitives.** The traversal here is not one request-deep: the poisoned name is *persisted in the model registry*, so the write target survives restart and re-materializes on load. Sweep create/register/save endpoints for name fields before theorizing about dedicated upload routes — the "name" field is the underrated write sink.
3. **Extension confinement is not scope confinement.** The sink only wrote `.json` files — but the process-writable `.json` surface includes the model registry and config/data files, so attacker-chosen content lands where the product itself trusts structure. Enumerate which files the service writes with the service's own privileges; that set is the real blast radius of any bounded write primitive.
4. **Same-product re-sweep rule holds again.** This is the second independent boundary class in Xinference on this wiki (Aug 21 `eval()` on Llama3 tool-call output, above; Oct 18 name-as-path traversal). One published boundary in an AI-serving product justifies re-sweeping the sibling surfaces — route families, validators, and file consumers — not treating the product as "covered."

Lab boundary: prove with a disposable Xinference on Windows (or a mocked path consumer on Linux recording the joined path), inert marker `.json` names, and a denied file-sink recorder; never overwrite real registry/config files, and check version and auth state before claiming unauthenticated reach (the default deployment, as in the August finding, ships without auth).

## Notes on skipped adjacent items

The same 2026-08-21 scan reviewed the JSONata expression-sandbox-escape family (published as a separate page), a GeoTools `jsonArrayContains` unauthenticated SQLi, and a large VulDB-style WordPress/TRENDnet/Joomla/Linux-kernel/Spring wave. The GeoTools and product-specific records are tracked to state without publication — they are product/DB-boundary records without a new reusable operator pattern in this window.
