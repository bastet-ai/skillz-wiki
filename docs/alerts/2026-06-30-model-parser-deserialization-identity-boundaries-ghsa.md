# Model parser, deserialization, and identity-extractor boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-j35x-w4gj-pf7w](https://github.com/advisories/GHSA-j35x-w4gj-pf7w) / CVE-2025-10996, [GHSA-8j3x-m868-cpw8](https://github.com/advisories/GHSA-8j3x-m868-cpw8) / CVE-2025-10995, [GHSA-m5gw-83w2-7749](https://github.com/advisories/GHSA-m5gw-83w2-7749) / CVE-2026-48207, [GHSA-m3v4-v5gx-7wf5](https://github.com/advisories/GHSA-m3v4-v5gx-7wf5) / CVE-2026-47117, and [GHSA-293q-567p-wmwq](https://github.com/advisories/GHSA-293q-567p-wmwq) / CVE-2026-47838.

These advisories are durable for operators because they expose repeatable trust-boundary tests: chemistry conversion services parsing untrusted SMILES or compressed molecule files, Python deserialization policies failing to cover reduce-state restoration, AI privacy-filter model names routing into `trust_remote_code=True`, and X.509 client-certificate CN parsing disagreeing with the authenticated identity actually selected.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j35x-w4gj-pf7w](https://github.com/advisories/GHSA-j35x-w4gj-pf7w) / CVE-2025-10996 | Open Babel `OBSmilesParser::ParseSmiles` | crafted SMILES strings could write past a heap buffer when parsed through `obabel`, `OBConversion`, or language bindings before 3.2.0 | Scientific file-conversion APIs are attack surface when web apps, notebooks, LIMS, or cheminformatics pipelines accept user molecule text. Prove in a lab harness only. |
| [GHSA-8j3x-m868-cpw8](https://github.com/advisories/GHSA-8j3x-m868-cpw8) / CVE-2025-10995 | Open Babel bundled `zipstream` gzip reader | crafted gzip-compressed chemistry files reached an overlapping `memcpy` / out-of-bounds write path | Include compressed-wrapper variants in parser-boundary tests; a safe extension or declared format does not remove decompressor risk. |
| [GHSA-m5gw-83w2-7749](https://github.com/advisories/GHSA-m5gw-83w2-7749) / CVE-2026-48207 | Apache Fory PyFory `ReduceSerializer` | reduce-state restoration and global-name resolution bypassed documented `DeserializationPolicy` validation hooks when strict mode was disabled | Treat policy-based deserializers as sinks: every constructor, reducer, global lookup, and state-restore path needs canary deny/allow tests. |
| [GHSA-m3v4-v5gx-7wf5](https://github.com/advisories/GHSA-m3v4-v5gx-7wf5) / CVE-2026-47117 | OpenMed privacy-filter model loader | user-controlled `model_name` substring matching routed attacker repositories into Hugging Face loading with `trust_remote_code=True` | AI service assessments should test model-name routing, repository authority, `auto_map`, and tokenizer/model config execution boundaries with inert repos. |
| [GHSA-293q-567p-wmwq](https://github.com/advisories/GHSA-293q-567p-wmwq) / CVE-2026-47838 | Spring Security `SubjectDnX509PrincipalExtractor` | malformed X.509 certificate CN values could make the extractor read the wrong username | mTLS/client-cert deployments need identity-extractor parser-differential tests: certificate subject string parsing must match the principal mapping policy. |

Adjacent Open Babel NULL-pointer and out-of-bounds-read advisories, duplicate Open Babel records, Apache Fory generic duplicate summaries, Spring Security duplicate advisory IDs, and availability-only parser/resource issues were processed without separate promotion because they did not add a distinct workflow beyond the boundaries above.

## Replayable validation boundaries

### Open Babel untrusted chemistry parser harness

- Preconditions: isolated lab host or CI job with vulnerable and fixed Open Babel versions, ASAN/UBSAN if building from source, and disposable molecule inputs only.
- Exercise both direct SMILES input and gzip-wrapped chemistry files through the same path the target uses: `obabel`, `OBConversion`, Python/Ruby/Java bindings, upload converters, or notebook helpers.
- Positive evidence is limited to sanitizer crash logs, process exit status, parser-format decision tables, and fixed-version negative controls. Do not attempt exploit reliability, shellcode, memory disclosure, or production conversion-service crashes.
- Include wrapper cases: raw molecule text, `.smi`, declared alternate formats, gzip-compressed files, and API calls where the service auto-detects format from extension or content.
- Negative controls: Open Babel 3.2.0 or later, input size/time limits, parser isolation, and format allowlists bound to the actual conversion code path.

### PyFory policy-bypass deserialization harness

- Preconditions: disposable Python process, affected `pyfory` version, strict mode disabled only in the lab, and a custom `DeserializationPolicy` that denies an inert canary callable/class.
- Create paired serialized payloads that try the same canary through normal object paths, reduce-state restoration, and global-name/module-attribute resolution.
- Positive evidence is a policy-denied canary being resolved or invoked through a reducer path while the same policy blocks the direct path.
- Keep canaries harmless: set an in-memory flag, return a marker string, or write to a temporary lab file. Do not deserialize payloads that launch processes, read environment variables, import cloud SDKs, or touch credentials.
- Negative controls: PyFory 1.0.0 or later, strict mode enabled, reducer/global lookup tests in CI, and policy hooks covering every restoration path.

### OpenMed privacy-filter model-routing harness

- Preconditions: owned OpenMed lab below 1.5.2, a disposable Hugging Face-compatible repository under your control, inert `auto_map` code that records only a marker, and no production PHI/PII.
- Send model names that contain the privacy-filter substring in unexpected positions, such as an owned namespace/repository name with `privacy-filter` embedded, and record which dispatcher path runs.
- Positive evidence is the service loading code or tokenizer/model config from the attacker-controlled repository because substring routing selected the privacy-filter loader with `trust_remote_code=True`.
- Do not load untrusted third-party repositories, exfiltrate prompts, process patient data, or run commands on production inference workers.
- Negative controls: OpenMed 1.5.2 or later, exact model allowlists, `trust_remote_code=False` for user-selectable models, and repository-owner pinning.

### Spring Security X.509 principal parser-differential harness

- Preconditions: lab Spring Security app using X.509 client-certificate authentication, affected `spring-security-web`, disposable users, and a test CA accepted only by the lab.
- Generate certificates with CN values that include escaping, separators, repeated attributes, unusual ordering, and malformed-but-accepted subject strings.
- Build a table for each certificate: raw subject DN, parsed CN from `SubjectDnX509PrincipalExtractor`, expected username, authenticated username, and authorization result for a harmless route.
- Positive evidence is a certificate authenticating as a different disposable user than the mapping policy intends.
- Do not use real client certificates, production CAs, customer usernames, or privileged admin routes.
- Negative controls: `SubjectX500PrincipalExtractor`, fixed Spring Security versions, strict subject mapping, and explicit certificate-to-account binding tests.

## August 2 Keras HDF5 external-link file-authority follow-up

[GHSA-m8wh-29wm-52mv / CVE-2026-9335](https://github.com/advisories/GHSA-m8wh-29wm-52mv) reports that Keras through 3.14.0 can dereference HDF5 `ExternalLink` objects when untrusted `.h5`, `.weights.h5`, or `.keras` artifacts reach `KerasFileEditor` or `keras.saving.load_weights`. The record says those paths bypass the `safe_get_h5_group` and `safe_get_h5_dataset` helpers used to reject external and soft links. This is a **model artifact -> secondary local file authority** boundary, not generic pickle execution.

The record was unreviewed at scan time. Confirm the exact Keras package, backend, container format, entry point, and corrected behavior. HDF5 external links reference HDF5 objects in another file; do not claim arbitrary byte-file disclosure unless the tested parser can actually expose that format and object.

### Patched HDF5-open matrix

1. Create a disposable directory containing a normal toy weights file, a second synthetic HDF5 file with one uniquely named dataset, and an empty sibling directory. No model cache, home directory, environment file, credentials, datasets, notebooks, or production weights should be present.
2. Build inert container fixtures whose link target is: an internal hard link, internal soft link, relative external link to the synthetic sibling HDF5 file, absolute external link to the same file, nonexistent file, nonexistent object, nested external-link chain, and symlink alias. Keep every target inside the disposable fixture tree for the first pass.
3. Patch `h5py.File` and relevant HDF5 file-open callbacks to record the canonical filename and object path, then return a sentinel before reading a secondary file. Invoke both `KerasFileEditor` and the exact application path to `keras.saving.load_weights`; helper-only reachability is insufficient when the assessed service never exposes that path.
4. Record archive/container provenance, outer model path, link type, raw linked filename, normalized/canonical secondary path, selected object, helper used, open-recorder event, and whether any dataset would be copied into editor state or model weights.
5. Compare direct helper calls that reject links with the two affected entry points. Repeat on the corrected commit/build and require rejection before any secondary open.
6. Only if sink-level dereference is explicitly required, allow one read of the synthetic sibling dataset and verify only its random marker hash. Never point a link at `/etc`, home directories, cloud configuration, model caches, customer datasets, or another tenant's files.

The bounded positive is **untrusted model artifact -> external-link metadata -> secondary synthetic HDF5 path reaches the file-open recorder outside the artifact's own logical object graph**. A stronger canary-only result is the sibling dataset marker appearing in `KerasFileEditor` state or loaded toy weights. Report editor extraction and weight loading separately; do not infer code execution, arbitrary non-HDF5 reads, or remote reachability without an independently demonstrated upload/import path.

This pattern generalizes to model, archive, and scientific-data formats that support external references. Inventory nested files, URIs, link tables, sidecar tensors, schema includes, and resolver callbacks even when the primary artifact passed extension, signature, or `safe_mode` checks.

## August 2 Transformers named-chat-template file-write follow-up

[GHSA-xrqw-3rrv-vx5w / CVE-2026-9856](https://github.com/advisories/GHSA-xrqw-3rrv-vx5w) reports that `huggingface/transformers <= 5.8.0.dev0` used attacker-controlled `chat_template` dictionary keys as filenames when `PreTrainedTokenizerBase.save_pretrained()` or `ProcessorMixin.save_pretrained()` emitted named templates. A malicious Hub repository could supply the legacy list-of-dictionaries form in `tokenizer_config.json`; each `name` becomes a dictionary key and then `additional_chat_templates/<name>.jinja`. A traversal-bearing name could therefore move the write outside the requested save directory when a downstream workflow downloaded and re-saved the tokenizer or processor.

The GitHub record was unreviewed at scan time and does not list a corrected release. The linked [Transformers commit](https://github.com/huggingface/transformers/commit/eaaaf8494dd5386634ae37d1d122212fdc315be5) adds resolved-parent checks to both save paths and regression tests. Confirm the exact package build and fixed-release provenance; do not infer that loading alone writes a file, because the vulnerable edge requires the later `save_pretrained()` operation.

### Recorder-first save matrix

1. Use an offline disposable environment containing affected and corrected Transformers builds, a toy tokenizer or processor, and a temporary root with `save/` plus one randomly named sibling canary path. Do not use a real model cache, home directory, notebook tree, startup file, credentials directory, or production inference worker.
2. Construct local synthetic `chat_template` dictionaries rather than downloading an unknown repository. Include a normal name, nested separator, parent traversal, absolute-path-like name, mixed separator, dot segment, Unicode lookalike, symlinked `additional_chat_templates` directory, and a template name that merely contains two dots. Keep every template body to a random inert marker.
3. Patch `open()` or the module's file-write helper to record the raw path, normalized path, canonical parent, open mode, and marker hash, then raise before creating a file outside the temporary `save/` tree. Exercise tokenizer and processor save paths separately; a helper-only call is not evidence that an application's import/export workflow reaches the sink.
4. Establish positive and negative controls: a valid named template should resolve immediately under `save/additional_chat_templates/`; traversal-shaped names should be rejected before the write recorder; a normal single-template save should retain expected behavior.
5. If a filesystem proof is explicitly required in an isolated affected build, permit only one write to the pre-created disposable sibling canary path and verify its random marker hash. Never overwrite an existing file, target shell or Python startup files, or combine the primitive with code execution.
6. Repeat against the commit above or a release proven to contain it. Require rejection before file creation in both `PreTrainedTokenizerBase` and every reachable `ProcessorMixin` subclass; the advisory specifically notes Idefics, Florence, Gemma, Phi, and Qwen-VL families as examples.

The bounded positive is **untrusted repository metadata -> named chat-template key -> canonical output path outside the requested tokenizer/processor save root -> write recorder**. Preserve the full application chain in evidence: repository authority, revision pin, `tokenizer_config.json` representation, class selected, call site that invokes `save_pretrained()`, requested save root, canonical destination, and fixed-build result. Report path acceptance, write reachability, overwrite semantics, and any later execution sink as separate claims.

This generalizes beyond model deserialization: enumerate attacker-controlled names that become sidecar files during model, tokenizer, processor, adapter, dataset, or checkpoint export. Loading policy, `trust_remote_code`, artifact signatures, and revision pins do not replace canonical destination confinement when trusted software later materializes repository metadata as filenames.

## August 7 Keras archive and layer-name final-path follow-up

Two reviewed Keras records add distinct **untrusted model/archive metadata -> filesystem destination** checks:

- [GHSA-hqp4-2352-xf5r / CVE-2026-11816](https://github.com/advisories/GHSA-hqp4-2352-xf5r) reports that Keras before 3.14.0 validated TAR and ZIP members against the process current working directory rather than the requested extraction destination. A process whose CWD is `/` therefore turns a narrow extraction root into a root-wide comparison boundary. The record also notes a blocked-ZIP-entry `AttributeError` and that Python 3.11 lacks the newer TAR `filter="data"` backstop.
- [GHSA-gh82-f9x8-5frx / CVE-2026-12479](https://github.com/advisories/GHSA-gh82-f9x8-5frx) reports that crafted layer names could reach `DiskIOStore.make()` as directory components. Affected ranges are Keras before 3.12.3 and 3.13.0 through 3.14.x; corrected releases listed by the record are 3.12.3 and 3.15.0.

### Archive extraction destination matrix

1. Use a disposable container with an empty credential-free filesystem view, affected and corrected Keras builds, Python 3.11 plus one newer supported interpreter, and temporary `cwd/`, `extract/`, and `sibling-canary/` directories. Never run the affected harness with host directories mounted.
2. Build local TAR and ZIP fixtures containing a normal file, nested file, parent traversal, absolute-path-like member, mixed separator, dot segment, duplicate name, directory symlink followed by child, and a sibling-prefix destination. Every file body should be a random inert marker.
3. Vary the process CWD independently from the extraction destination: `/`, the temporary root, `extract/`, and an unrelated sibling. Record member name, member type, raw destination, normalized destination, canonical parent, CWD, interpreter, Keras build, filter selected, and exception.
4. Patch the final file-open, directory-create, rename, and link syscalls to record then deny any canonical destination outside `extract/`. A positive is an outside-root destination reaching a denied sink because validation used CWD; an `AttributeError` without an outside-root sink is availability behavior and should be reported separately.
5. Repeat on Keras 3.14.0 or a build proven to contain the archive fix. Require rejection before directory or file creation for both TAR and ZIP, including Python 3.11. Do not assume the interpreter's optional TAR filter covers ZIP or application-specific destination logic.

### `DiskIOStore` layer-name matrix

1. Construct a toy model locally with inert layer and variable markers. Exercise the exact application save/load path that reaches `DiskIOStore.make()`; a direct helper call establishes sink behavior but not remote reachability.
2. Test ordinary names, parent segments, dot segments, nested separators, mixed separators, absolute-path-like names, Unicode separator lookalikes, sibling-prefix names, and a symlinked intermediate directory. Preserve the serialized artifact metadata so the model-controlled provenance is explicit.
3. Patch directory creation and file writes to capture the layer name, temporary store root, joined path, normalized path, canonical path, operation, and marker hash, then deny outside-root operations. Keep load-time and save-time traces separate.
4. Compare the affected ranges with 3.12.3 and 3.15.0 controls. The bounded positive is **artifact-controlled layer name -> canonical `DiskIOStore` path outside its temporary root -> denied filesystem sink**. Directory creation, file write, overwrite, and later execution are separate claims.

For either issue, permit a real filesystem proof only inside a disposable temporary tree and only to a pre-created sibling marker path. Never target startup files, notebooks, datasets, model caches, credentials, or production training/inference workers. Do not infer code execution from path control without an independently proven executable consumer.

## August 7 follow-up: Keras deserialization and external-dataset authority

Four additional reviewed records widen the model-artifact matrix beyond final output paths:

- [GHSA-v2w2-w228-c444 / CVE-2026-12484](https://github.com/advisories/GHSA-v2w2-w228-c444) reports that `TorchModuleWrapper.from_config()` could reach `torch.load(..., weights_only=False)` when no ambient `SafeModeScope(True)` existed.
- [GHSA-5gwj-m78q-7pq3 / CVE-2026-12481](https://github.com/advisories/GHSA-5gwj-m78q-7pq3) reports that `Lambda.from_config()` treated an unset `safe_mode=None` differently from an explicit safe scope, allowing marshalled Lambda code through direct layer deserialization and related clone/deserialize paths.
- [GHSA-26c4-7vv6-867j / CVE-2026-12480](https://github.com/advisories/GHSA-26c4-7vv6-867j) reports that HDF5 Virtual Datasets were not rejected before their external source files were resolved. This is adjacent to, but distinct from, the earlier `ExternalLink` record: test both object links and VDS source mappings.
- [GHSA-58hv-7753-xmfq / CVE-2026-12482](https://github.com/advisories/GHSA-58hv-7753-xmfq) reports that Keras TAR filtering validated regular entries but did not apply equivalent destination checks to symlink entries, particularly where Python 3.10/3.11 lacked a newer interpreter backstop.

The listed affected ranges for these records are Keras before 3.12.3 and 3.13.0 through 3.14.x; the corrected releases are 3.12.3 and 3.15.0. Confirm the exact branch and backport used by the assessed service.

### Deserializer entry-point and ambient-policy matrix

1. Use an offline disposable process with toy Keras configurations only. Replace `torch.load`, Lambda bytecode reconstruction, imports, and process/file APIs with recorders that return inert sentinel objects or raise before execution.
2. Invoke the same synthetic layer configuration through direct `from_config()`, `keras.layers.deserialize()`, model loading, and `clone_model()` where applicable. Run each with an explicit safe scope, explicit unsafe opt-in, `safe_mode=None`, and no ambient scope.
3. Record entry point, layer type, serialized field, caller-supplied mode, ambient scope, final loader arguments, and whether the denied reconstruction sink was reached. Do not treat one guarded top-level loader as proof that public helper and clone paths inherit the same policy.
4. The bounded positive is **untrusted layer configuration -> unset or lost ambient policy -> denied pickle or marshalled-code reconstruction sink**. Do not execute a real pickle gadget, marshalled command, import side effect, or live model code.
5. Repeat on 3.12.3 and 3.15.0 controls. Require default rejection at every reachable entry point while preserving an explicit, documented unsafe opt-in only in the isolated lab.

### VDS, external-link, and TAR-link differential matrix

1. Extend the earlier HDF5 fixture tree with a synthetic external HDF5 file containing one random dataset marker. Build separate containers using an `ExternalLink`, a Virtual Dataset source mapping, an internal dataset, a missing source, an absolute in-tree alias, and a symlink alias.
2. Patch HDF5 open/resolver callbacks and record artifact path, object type, VDS/link metadata, raw secondary filename, canonical filename, selected object, and calling Keras entry point. Deny before reading anything outside the disposable tree.
3. For TAR, pair regular-file, regular-directory, symlink, hard-link, symlink-then-child, and duplicate-entry fixtures that express the same canonical destination. Patch final create/link/open syscalls and deny every outside-root destination.
4. A positive is **artifact metadata -> external HDF5 source or archive link -> denied secondary file/open/link sink** while the equivalent internal object remains functional. Report VDS resolution, external-link resolution, symlink creation, later write-through, and file disclosure as separate edges.
5. Never reference host files, model caches, notebooks, datasets, credentials, startup files, or another tenant's artifacts. A canary read or link proof, if explicitly required, must stay inside the disposable root.

## August 10 follow-up: bind sharded checkpoint entries to the checkpoint root

[GHSA-4j2p-28q2-5m79 / CVE-2026-69112](https://github.com/advisories/GHSA-4j2p-28q2-5m79) reports that Hugging Face Accelerate through 1.14.0 accepts relative parent paths or absolute paths from sharded-checkpoint `weight_map` entries in `load_checkpoint_in_model()` and `load_checkpoint_and_dispatch()`. The record also identifies named pipes as an availability sink. Treat the index as a manifest that selects secondary files; approving the top-level checkpoint directory is not authority to open every path named inside it.

Use an offline disposable root with `checkpoint/`, one ordinary synthetic shard, one random sibling canary file, and a FIFO that is never opened for blocking I/O. Patch file open, `safetensors`/PyTorch shard loading, and FIFO detection so each candidate canonical path is recorded and denied before bytes are read.

Test both entry points with ordinary relative shard names, nested in-root names, parent segments, absolute paths, sibling-prefix names, mixed separators, dot segments, symlinked intermediate directories, nonexistent files, duplicate tensor mappings, and FIFO-shaped entries. Record index provenance, revision pin, tensor key, raw `weight_map` value, checkpoint root, normalized and canonical shard path, file type, loader selected, and first denied open.

A bounded positive is **untrusted checkpoint index -> `weight_map` entry -> canonical sibling-canary path reaches the denied shard-open sink**. For FIFO entries, evidence should stop at `lstat`/file-type and attempted loader selection; do not permit a blocking read merely to prove denial of service. Replay byte-identical fixtures against the corrected commit or release and require rejection before any outside-root or non-regular-file open.

Do not point manifests at host configuration, model caches, notebooks, datasets, credentials, devices, sockets, or another tenant's model. Report path selection, readable-file reachability, FIFO handling, deserialization, and any later model execution as separate effects.

## September 21 follow-up: ML library loaders still pickle-load by default, and "fixed" narratives lie

Three records in the 2026-09-21 00:30Z GitHub advisory wave are low-severity VulDB-style entries, but their advisories carry a durable verification lesson for AI/ML platform assessments: the default-unsafe pickle model loader is a **per-function, per-package property that can regress**, and public fix narratives routinely overstate coverage.

- [GHSA-rh54-3493-vqgc / CVE-2026-94093](https://github.com/advisories/GHSA-rh54-3493-vqgc) — DLR-RM stable-baselines3 through 2.9.0: `PPO.load`, `load_replay_buffer`, and `VecNormalize.load` (`save_util.py`) unpickle attacker-supplied model/replay/normalizer artifacts with no safe mode. The advisory states the timeline explicitly: a `weights_only=True` hardening **landed in v2.9.0's tensor load path and was then reverted on master** (PR #1913, "Hotfix: revert loading with weights_only=True") for PyTorch 1.13 compatibility, and the earlier "fix" (PR #41) only gated the Hugging Face Hub loader in the *separate* `huggingface_sb3` package — the core `stable_baselines3` load APIs remained exploitable.
- [GHSA-9h85-xr59-9fh8 / CVE-2026-94091](https://github.com/advisories/GHSA-9h85-xr59-9fh8) — gensim through 4.4.0: `SaveLoad.load` (`gensim/utils.py`) still calls unsafe `pickle.load`; the upstream issue was closed the same day with no comment, PR, or fix, and repo HEAD predates the report — the unsafe default survives at develop HEAD.
- [GHSA-jf58-7v68-wxqh / CVE-2026-94092](https://github.com/advisories/GHSA-jf58-7v68-wxqh) — dmlc dgl through 2.1.0: `load_info`/`_read_torch_data` (`utils.py`) deserialize attacker-supplied graph/data artifacts; project unresponsive, no gate.

The reusable axes:

1. **Fingerprint the installed loader call, not the changelog.** A library version advertised as hardened may have reverted the hardening on master (compat reverts are common in the PyTorch ecosystem), and one guarded entry point does not cover sibling load APIs. Patch/read the actual `torch.load` / `pickle.load` call sites in the *installed* package (grep for `weights_only`, `RestrictedUnpickler`, `safe_load`) rather than trusting the release note.
2. **A CVE fix in package A says nothing about package B.** The stable-baselines3 case gated only the `huggingface_sb3` hub loader while core `load()` APIs stayed unsafe; duplicate-closed issues can hide "fix lives elsewhere" scope reductions. When re-testing a previously reported deserialization finding, enumerate every load function on the artifact surface (`load`, `load_replay_buffer`, normalizer/statistics loaders, graph/dataset loaders), not just the originally reported one.
3. **Stagnant ML repos keep default-unsafe defaults.** gensim and dgl both have published exploits with no fix path. For any ML stack in a target, treat `.pkl`/`.pt`/`.zip` model, replay-buffer, normalizer, and graph artifacts as code-execution channels from untrusted storage or upload endpoints.

### Bounded validation

Use an offline disposable process with the installed package version. Replace `pickle.Unpickler.find_class`, `torch.load`, and process/file APIs with recorders; craft a benign pickle whose `__reduce__` targets a recording canary (in-memory flag or temp-file marker). Invoke each sibling loader (`PPO.load`, `load_replay_buffer`, `VecNormalize.load`, `SaveLoad.load`, DGL `load_info`) against a downloaded-from-lab-storage artifact and record loader selected, `weights_only`/restricted flag value, and whether the canary resolves. A bounded positive is **untrusted artifact -> default-unsafe loader -> canary reaches the denied sink**. Do not run real gadgets, do not execute on shared hosts, and do not pull third-party model hubs into the harness. Pair every positive with the installed version string and the relevant upstream issue/PR state (open, reverted, closed-unfixed) in the report — the upstream disposition is part of the finding.

Adjacent records in the same wave were processed without promotion: Netcore NBR200V2 router CGI/traceroute/LAN-config command injection trio (CVE-2026-94097/94096/94095, familiar unauthenticated-arg-to-shell router class with public PoCs), OpenClaw canvas-host whole-file-buffer DoS (CVE-2026-94094), and a Manalyze PE-debug integer-underflow parser fix (CVE-2026-94090).

## Reporting notes

- Lead with the exact boundary crossed: **untrusted molecule input to native parser**, **deserialization policy to reduce/global lookup**, **model-name substring to remote code loader**, **unset ambient safe mode to pickle/bytecode reconstruction**, **model/archive metadata to canonical filesystem destination**, **checkpoint manifest to secondary shard path**, **HDF5 metadata to a secondary file resolver**, **model metadata name to sidecar-file destination**, or **certificate subject string to authenticated username**.
- Include affected and fixed versions, the minimal canary input shape, expected denial or safe parse, observed result, and a fixed-version negative control.
- Keep evidence scoped and inert: sanitizer traces, temp-file markers, owned model repos, fake users, lab CAs, and synthetic molecule files only.
