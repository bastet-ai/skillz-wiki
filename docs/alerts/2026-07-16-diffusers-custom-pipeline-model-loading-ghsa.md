# Diffusers custom-pipeline model-loading boundary checks

Source: hourly offensive-security scan, 2026-07-16 GitHub advisory update, with a LightGlue model-loader follow-up on 2026-07-21. Primary entries: [GHSA-j7w6-vpvq-j3gm](https://github.com/advisories/GHSA-j7w6-vpvq-j3gm) / CVE-2026-44827 and [GHSA-fgcw-684q-jj6r](https://github.com/advisories/GHSA-fgcw-684q-jj6r) / CVE-2026-5241.

This advisory is durable for operators because it exposes a reusable AI supply-chain boundary: a model repository that appears to load through a default `DiffusionPipeline.from_pretrained("repo")` call can still cross into Python dynamic-module execution. The bug comes from the `custom_pipeline=None` default being formatted as the filename `None.py` during the second pipeline-class resolution step, after the earlier `trust_remote_code` gate has already decided no custom pipeline was requested.

!!! warning "Authorized validation only"
    Keep proofs to disposable model repositories, offline/local Hub fixtures, sandboxed inference workers, fake environment variables, and inert marker files. Do not load untrusted model repositories on production inference hosts, do not execute attacker-supplied code, do not collect real API tokens, model weights, prompts, datasets, SSH material, cloud credentials, or user files, and do not publish weaponized model archives.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j7w6-vpvq-j3gm](https://github.com/advisories/GHSA-j7w6-vpvq-j3gm) / CVE-2026-44827 | Hugging Face Diffusers `DiffusionPipeline.from_pretrained()` before `0.38.0` | Default `custom_pipeline=None` is converted into `None.py`; a repository containing that file can be downloaded and dynamically loaded even when the caller did not pass `custom_pipeline=` or `trust_remote_code=True` | Treat AI model loading as code loading. Validate the actual dynamic-module chokepoints, cached snapshots, and repository file inventory instead of relying only on call-site arguments or benign-looking `model_index.json` class names. |
| [GHSA-fgcw-684q-jj6r](https://github.com/advisories/GHSA-fgcw-684q-jj6r) / CVE-2026-5241 | Transformers LightGlue loading path before `5.5.0` | repository-controlled `config.json` can override `trust_remote_code` in `LightGlueConfig` and propagate the untrusted value into nested `AutoConfig.from_pretrained()` calls | Extend remote-code trust tests to third-party wrappers: trace every nested `from_pretrained()` and dynamic-module resolver rather than trusting the outer flag or the model card. |

The operator-relevant distinction is that no suspicious call-site option is required. A target review that only searches for `trust_remote_code=True`, `custom_pipeline=`, or config-declared custom classes can miss the path when an otherwise normal model snapshot contains a root-level `None.py` that shadows a legitimate pipeline class.

## Replayable validation boundaries

### Diffusers silent custom-pipeline execution check

1. Build an isolated Python lab with Diffusers below `0.38.0`. Use a disposable virtual environment, a temp Hugging Face cache directory, and no live service credentials in the process environment.
2. Create or mirror a model fixture that has:
   - a normal-looking `model_index.json` whose `_class_name` names a legitimate Diffusers pipeline class for the chosen fixture;
   - the minimum inert model files needed for the pipeline loader path to progress far enough for class resolution; and
   - a root-level `None.py` defining a class that subclasses or shadows the expected pipeline class and performs only a harmless marker action, such as writing a file under a temporary lab directory.
3. Call only the default loader shape from the victim side:

   ```python
   from diffusers import DiffusionPipeline

   pipe = DiffusionPipeline.from_pretrained("<owned-lab-model-or-local-snapshot>")
   ```

   Do not pass `custom_pipeline=`, `trust_remote_code=True`, alternate indexes, real tokens, or production model IDs.
4. Record whether the loader succeeds and whether the inert marker proves `None.py` was imported or executed despite the default call shape.
5. Repeat against Diffusers `0.38.0` or newer and record the expected `ValueError` / refusal at the dynamic-module load chokepoint.
6. Add controls for a fixture with no `None.py`, an explicit custom-pipeline fixture that correctly requires `trust_remote_code=True`, a pre-populated local snapshot cache, and an empty or read-only temp cache.

Report this as **benign-looking model repository -> default Diffusers pipeline load -> implicit `None.py` dynamic module -> code-execution boundary without explicit remote-code trust**. Evidence should be version, loader call shape, fixture file inventory, marker path under the temp lab directory, cache state, and patched negative control.

### Static model-repository triage for bug-bounty and red-team reviews

Use this checklist when reviewing AI inference code paths, CI jobs, notebooks, or internal model registries that call Diffusers loaders:

| Check | What to capture | Why it matters |
| --- | --- | --- |
| Loader arguments | Search for `DiffusionPipeline.from_pretrained`, `AutoPipeline*`, wrapper functions, and whether `trust_remote_code`, `custom_pipeline`, `revision`, and local snapshot paths are pinned | The vulnerable path can trigger even when `trust_remote_code` and `custom_pipeline` are absent, so absence is not enough evidence of safety. |
| Snapshot file inventory | List root-level Python files and component-subdirectory Python files in model snapshots; flag `None.py` and unexpected `*.py` files | The trust boundary is the dynamic module file actually resolved, not just `model_index.json`. |
| Cache provenance | Identify whether workers use pre-populated Hub caches, shared cache volumes, CI artifacts, or user-supplied local model directories | The advisory notes the file can be present from a cached or local snapshot, not only freshly downloaded. |
| Class-name shadowing | Compare `_class_name` against expected built-in pipeline classes and inspect whether a local Python file defines the same class name | A malicious fixture can look like it uses a legitimate pipeline while loading attacker-controlled Python. |
| Patch control | Re-run the same fixture on Diffusers `0.38.0+` | The fix moves the gate to the dynamic-module load chokepoint, which is the control to prove. |

Keep static evidence to repository metadata, filenames, hashes, and inert local fixtures. Do not download or execute suspicious public models during an assessment unless the engagement explicitly authorizes sandboxed malware-style handling.

## July 21 LightGlue nested-loader follow-up

LightGlue adds a second reusable failure mode: a library wrapper can pass model metadata into Transformers dynamic-module resolution even when the caller believes remote code is disabled. Test it with the same disposable-repository discipline as Diffusers, but capture the complete nested call chain.

1. Create an offline or private LightGlue-compatible model fixture containing ordinary inert model metadata and one local Python module whose only effect is writing a marker under a temporary directory.
2. Call the application's actual LightGlue loading path with `trust_remote_code=False` at every public call site that exposes the option.
3. Trace repository resolution, `LightGlueConfig` parsing, nested `AutoConfig.from_pretrained()` calls, `auto_map` or equivalent class metadata, dynamic-module cache writes, and Python imports. A global CLI or wrapper flag is not sufficient evidence unless it reaches the final resolver.
4. Compare a fixture without dynamic-module metadata, the inert module fixture, and Transformers `5.5.0` or newer. Keep the process offline after the fixture is staged.
5. Record whether the marker module was downloaded, cached, imported, or instantiated; distinguish each stage instead of claiming execution from file presence alone.

Report this as **model repository metadata -> nested third-party loader -> dynamic Python module resolution despite remote-code opt-out**. Include the outer and inner loader calls, flag values, resolved repository revision, module/cache path, import trace, and patched negative control. Do not use public malicious models, real hub tokens, production inference workers, shell commands, network callbacks, or credential-reading canaries.

## Reporting notes

- Lead with preconditions: Diffusers version, loader function, model source trust level, revision pinning, cache state, sandbox boundary, and whether any user-controlled model ID or local snapshot path reaches the loader.
- Prefer a decision table over payload details: model fixture, call shape, `None.py` present, cache state, expected remote-code gate, observed marker, patched result.
- Redact model registry tokens, private model names, prompts, datasets, local cache paths beyond synthetic temp directories, environment variables, and any marker content that reveals host identity.
- This finding pairs naturally with broader AI model-loading reviews for `trust_remote_code`, sidecar artifacts, revision pins, and local snapshot ingestion. The durable lesson is to review dynamic-module resolution and cached files as first-class code-execution surfaces.
