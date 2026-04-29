# InstructLab trust_remote_code execution and logs_dir path traversal (GHSA-rxpq-xgqx-fr7p / GHSA-pqmg-c2j8-fq92)

**Signal:** GitHub Security Advisories updated **2026-04-29**. InstructLab advisories highlight two AI-workflow boundary failures: remote model code execution and local path traversal.

## What it is
Affected package: pip `instructlab <= 0.26.1`.

- `GHSA-rxpq-xgqx-fr7p` / `CVE-2026-6859`: `linux_train.py` hardcodes `trust_remote_code=True` when loading HuggingFace models. A malicious model can execute arbitrary Python when a user runs `ilab train`, `download`, or `generate` against it.
- `GHSA-pqmg-c2j8-fq92` / `CVE-2026-6855`: the chat session handler can be abused through a manipulated `logs_dir` parameter to create directories and write files outside the intended location.

References:

- <https://github.com/advisories/GHSA-rxpq-xgqx-fr7p>
- <https://github.com/advisories/GHSA-pqmg-c2j8-fq92>

## Triage
1. Find workstations, CI runners, and training boxes running InstructLab `<= 0.26.1`.
2. Review recent HuggingFace model identifiers and repositories used with `ilab train`, `download`, or `generate`.
3. Check whether untrusted users can choose model IDs, model revisions, training inputs, or `logs_dir` values.
4. Inspect unexpected files/directories created near project roots, shell startup files, service directories, and writable application paths.

## Mitigation
- Upgrade when a fixed release is available; until then, do not load untrusted models with remote code execution enabled.
- Pin model repositories to trusted owners and immutable revisions; verify model code before use.
- Run model download/training/generation in disposable, network-restricted containers or VMs with no host secrets mounted.
- Canonicalize and constrain log/output paths to an owned workspace root; reject `..`, symlinks, absolute paths, and post-normalization escapes.

## Detection ideas
- Hunt for Python process launches from model cache directories or HuggingFace repository snapshots.
- Review shell history, CI logs, and audit logs for `ilab` commands referencing unfamiliar model IDs.
- Search for new files written outside expected InstructLab log directories shortly after chat/session activity.
- Monitor outbound connections from training hosts to destinations unrelated to expected model downloads.

## Durable lesson
Model repositories can be code repositories. AI tooling should default to pinned, reviewed code paths and sandboxed execution, especially when a model loader exposes `trust_remote_code`.
