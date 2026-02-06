# 2026-02-06 — PHPUnit unsafe deserialization in PHPT code coverage handling (GHSA-vvj3-c3rp-c85p / CVE-2026-24765)

**Upstream advisory:** https://github.com/advisories/GHSA-vvj3-c3rp-c85p

## What happened
PHPUnit’s PHPT runner had a code path that **unserialized code coverage data** from a file without sufficient validation.

The practical risk is primarily **CI/CD pipeline compromise** (“poisoned pipeline execution”): if an attacker can cause a malicious `*.coverage` file to exist *before* PHPT tests run, the test run may deserialize attacker-controlled objects and execute gadget chains.

This is most relevant in environments that:
- run test suites automatically on untrusted PRs / forks
- reuse workspaces between jobs
- allow contributors to write files into the working directory (including via build steps)

## Why this matters (durable lesson)
Even if a vulnerability is “local file write required”, CI systems often **create that write capability** for attackers:
- a malicious PR can add files to the repo
- build steps can generate artifacts in predictable paths
- cached workspaces or reused runners can preserve attacker-planted files

Treat **“tests are safe”** as a myth when executing untrusted code.

## Defender guidance
### If you run PHPUnit PHPT with coverage
- **Upgrade PHPUnit** to a patched version (per advisory).
- Run CI on **ephemeral, isolated runners** (fresh workspace each job).
- **Do not reuse** artifacts/workspaces across trust boundaries.
- If you must run untrusted PRs, run them in a **sandboxed job** with:
  - no secrets
  - locked-down network egress
  - least-privilege filesystem

### Add a tripwire: pre-existing coverage files
A simple hardening check is to fail fast if unexpected coverage files exist before tests run.

Example (bash) — adjust paths/globs to your setup:

```bash
set -euo pipefail

# Fail if any pre-existing coverage artifacts are present
if find . -type f -name '*.coverage' -o -name '.coverage' | grep -q .; then
  echo "ERROR: pre-existing coverage files found; possible workspace contamination" >&2
  exit 1
fi
```

## Attacker notes (for testers)
- Look for CI workflows that enable coverage on PRs.
- Look for workspace reuse/caching across jobs.
- Identify where PHPUnit expects coverage artifacts for PHPT.

## References
- GHSA: https://github.com/advisories/GHSA-vvj3-c3rp-c85p
- OWASP CI/CD Risk (Poisoned Pipeline Execution): https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution
