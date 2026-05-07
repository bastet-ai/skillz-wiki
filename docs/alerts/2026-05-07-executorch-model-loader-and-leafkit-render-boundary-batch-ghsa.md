# ExecuTorch model-loader and LeafKit render-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where model files and template values cross trust boundaries: six ExecuTorch model/method loading memory-safety advisories and one LeafKit collection rendering XSS advisory.

## Advisories covered

- **ExecuTorch heap-based buffer overflow in model loading** — [GHSA-xc7w-r669-48pf](https://github.com/advisories/GHSA-xc7w-r669-48pf): malformed model data can crash the runtime and may enable code execution. Affected packages include `executorch`, `org.pytorch:executorch-android`, and Swift `github.com/pytorch/executorch`; patch to **0.7.0**.
- **ExecuTorch integer overflow in model loading** — [GHSA-hj95-mhgf-jxc4](https://github.com/advisories/GHSA-hj95-mhgf-jxc4): size arithmetic can create overlapping allocations, turning untrusted model bytes into memory corruption. Patch to **0.7.0**.
- **ExecuTorch heap buffer overflow in method loading** — [GHSA-h952-963h-rv99](https://github.com/advisories/GHSA-h952-963h-rv99): method payload loading can overflow heap buffers; Android/Swift fixed at **0.7.0-rc1** or later and Python at **0.7.0**.
- **ExecuTorch out-of-bounds access in model loading** — [GHSA-f9hx-c6jf-3qxm](https://github.com/advisories/GHSA-f9hx-c6jf-3qxm): malformed models can drive reads/writes outside expected bounds. Patch to **0.7.0**.
- **ExecuTorch heap buffer overflow in model loading** — [GHSA-9m39-3mf3-xwch](https://github.com/advisories/GHSA-9m39-3mf3-xwch): another loader path can corrupt memory before model execution begins. Patch to **0.7.0**.
- **ExecuTorch integer overflow placing objects outside allocations** — [GHSA-84m3-f99p-cqx5](https://github.com/advisories/GHSA-84m3-f99p-cqx5): object placement arithmetic can escape the allocated memory area. Patch to **0.7.0**.
- **LeafKit collection-value escaping bypass** — [GHSA-6jj5-j4j8-8473](https://github.com/advisories/GHSA-6jj5-j4j8-8473): printing Arrays or Dictionaries through `#(value)` can skip HTML escaping when `LeafData.htmlEscaped()` treats conversion as ambiguous. Patch Swift `github.com/vapor/leaf-kit` to **1.14.2**.

## Why this is durable

Model loaders are parsers for high-privilege binary formats. Treating `.pte`/mobile model artifacts as trusted because they are "just models" repeats the same mistake as trusting images, archives, or fonts. Template engines have the mirror problem: escaping needs to be tied to the output sink and value shape, not to a happy-path scalar conversion. Both classes fail when boundary checks live inside format-specific convenience code instead of a shared trust policy.

## Immediate triage

1. Patch ExecuTorch everywhere it ships: Python services, Android apps, iOS/macOS Swift integrations, edge devices, and CI/model-conversion containers. Prefer **0.7.0+** across ecosystems.
2. Inventory all paths that accept user-, partner-, plugin-, marketplace-, or remotely-updated ExecuTorch models/methods. Treat those paths as untrusted file parsing even if the model later runs locally.
3. Temporarily gate untrusted model ingestion behind sandboxed workers with memory, CPU, filesystem, network, and secret isolation; a loader crash should not expose the host app or tenant data.
4. Patch LeafKit to **1.14.2+** and search Vapor/Leaf templates for `#(...)` expressions that print arrays, dictionaries, decoded JSON, request-derived collections, metadata, or validation errors.
5. Add regression tests that render collection values containing `<script>`, event handlers, nested dictionaries, and mixed scalar/collection data into every HTML sink used by the app.

## Hunt prompts

- `executorch` package versions below 0.7.0 in Python lockfiles, mobile build manifests, model-serving images, and embedded SDK vendor directories.
- Upload, sync, or OTA paths that write model files into locations consumed by mobile/edge inference runtimes.
- Crash telemetry around model loading, method loading, allocation failures, integer-overflow checks, or malformed FlatBuffer/model metadata.
- Leaf templates rendering request, session, JSON, form, or database-backed collection values directly with `#(value)`.
- XSS reports where scalar values are escaped but arrays/dictionaries render raw delimiters or embedded HTML.

## Durable controls

- Model artifacts need the same controls as archives and media: provenance, signature verification, content scanning, size/depth limits, parser fuzzing, and sandboxed loading.
- Keep model parsing and execution in a least-privilege process; only pass validated tensors or narrow results back to the application boundary.
- Centralize integer and bounds checks in loader primitives so every model, method, tensor, and metadata path uses the same overflow-safe arithmetic.
- Make template escaping context-aware and type-aware; collections should serialize through an explicitly escaped encoder, not fallback `String` conversion.
- Regression-test non-scalar rendering paths. Escaping tests that only cover strings miss the exact class LeafKit exposed.
