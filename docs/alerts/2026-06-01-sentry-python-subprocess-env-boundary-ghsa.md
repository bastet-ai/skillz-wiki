# Sentry Python SDK subprocess environment boundary

Sources: [GHSA-g92j-qhmh-64v2](https://github.com/advisories/GHSA-g92j-qhmh-64v2), [upstream Sentry Python SDK advisory](https://github.com/getsentry/sentry-python/security/advisories/GHSA-g92j-qhmh-64v2), [fix PR #3251](https://github.com/getsentry/sentry-python/pull/3251), [patch commit 763e40a](https://github.com/getsentry/sentry-python/commit/763e40aa4cb57ecced467f48f78f335c87e9bdff), [Sentry SDK 2.8.0](https://github.com/getsentry/sentry-python/releases/tag/2.8.0), and [Sentry SDK 1.45.1](https://github.com/getsentry/sentry-python/releases/tag/1.45.1), updated on 2026-06-01.

Sentry's Python SDK before `2.8.0` and before the `1.45.1` backport could make `subprocess` calls inherit the parent process environment even when the caller explicitly passed `env={}`. The offensive operator lesson is broader than Sentry: do not trust instrumentation, tracing, or monkey-patched standard-library wrappers to preserve secret-stripping boundaries. When a target relies on `env={}` to launch untrusted helpers, converters, plugins, AI tools, or build steps, verify the actual child-process environment with canaries rather than assuming Python's default contract still holds.

## Advisory signal

- **Boundary mismatch** — Python `subprocess` normally treats `env={}` as an empty environment. Affected Sentry SDK versions' default Stdlib integration wrapped subprocess handling in a way that caused the full parent environment to reach the child anyway.
- **Secret-disclosure primitive** — the issue is most useful where a web app, CI worker, agent framework, document converter, plugin runner, or test harness invokes attacker-influenced commands while attempting to suppress secrets with `env={}`.
- **Instrumentation dependency clue** — the vulnerable package is `sentry-sdk`; ranges are `<1.45.1` and `>=2.0.0a1,<2.8.0`. The Stdlib integration is enabled by default unless explicitly disabled.
- **Impact shape** — this does not create command execution by itself. It upgrades an already-reachable subprocess execution surface into a potential environment-secret exposure when the child process can print, log, exfiltrate, upload, cache, or otherwise reflect its environment.
- **Patch shape** — fixed releases preserve explicit empty-environment behavior. A reliable retest should show a child process launched with `env={}` receiving no ambient secrets.

## Operator triage

1. Look for Python services that import `sentry_sdk`, initialize Sentry, and spawn subprocesses for user-influenced work: format conversion, linters, template rendering, agent tools, repository analysis, sandboxed code execution, PDF/image processing, CI tasks, or plugin hooks.
2. Confirm package versions from lockfiles, container images, runtime banners, dependency reports, or `pip show sentry-sdk` output where authorized.
3. Prioritize subprocess calls that use `env={}` or claim to launch with a stripped environment. The bug matters when the developer intentionally tried to remove secrets.
4. Identify whether the child process output is observable by the tester: HTTP response, job artifact, build log, error page, webhook callback, model/tool transcript, uploaded file, or application log visible through an authorized account.
5. Use a benign canary variable in a lab or explicitly authorized test path. Prove that the canary appears in the child environment despite `env={}`; do not attempt to dump real production secrets.
6. Retest patched versions or Stdlib-integration-disabled deployments to show the boundary closes: the same child process should see only the explicit environment supplied by the parent.

## Safe validation workflow

Use a local or program-approved reproduction rather than live secret discovery:

```python
import os
import subprocess
import sentry_sdk

os.environ["SKILLZ_CANARY_ENV"] = "skillz-env-boundary-test"
sentry_sdk.init(dsn="")

print(subprocess.check_output(["env"], env={}).decode())
```

Expected boundary behavior is an empty result. Affected Sentry SDK versions can print the inherited `SKILLZ_CANARY_ENV` and any other parent environment variables.

For application testing, adapt the same idea without exposing secrets:

1. Arrange for a tester-controlled canary variable in a non-production worker, preview environment, or explicitly approved job runner.
2. Trigger the smallest subprocess path that should receive `env={}`.
3. Capture only whether the canary appears. Do not collect ambient cloud keys, database URLs, API tokens, or customer data.
4. If the application cannot support a canary, stop at static evidence: vulnerable `sentry-sdk` range, Sentry initialized with default integrations, and a sensitive `env={}` subprocess call reachable from attacker-influenced input.

## Reporting heuristics

- Frame the finding as an environment-isolation bypass in subprocess execution, not as a generic dependency update.
- Show the intended boundary: the code passes `env={}` or otherwise documents that the child process should run without parent secrets.
- Show the observed boundary failure with a canary variable, affected `sentry-sdk` version, and the subprocess call site.
- Explain exploit preconditions clearly: an attacker still needs influence over a child process that can reveal or use its environment.
- Keep evidence minimal and redacted. A single canary value is enough; real secrets should be replaced with key names, hashes, or counts if the program requests impact context.
- If the target uses tracing/instrumentation beyond Sentry, recommend the same class of test: verify child-process environment allowlists after integrations are loaded, not only in isolated unit tests.
