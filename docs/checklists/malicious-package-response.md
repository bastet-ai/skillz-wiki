# Malicious package response (npm/pip/etc.)

## When to use this
Use this checklist if you learn you **installed a malicious package** (typosquat, dependency confusion, hijacked maintainer account, etc.).

Treat it as a **host compromise** event until proven otherwise.

## Immediate actions (first hour)
1) **Stop the bleeding**
- Identify *where* the package ran (dev laptop, CI runner, build host, prod).
- Stop affected jobs/services.
- If feasible, **isolate the host** (network off / quarantine VLAN).

2) **Assume secrets are burned**
- Any secrets present on the machine while the package was installed/running are suspect:
  - cloud keys, CI tokens, SSH keys, signing keys, `.npmrc`/`.pypirc`, API tokens, browser cookies
- **Rotate secrets from a different, known-clean machine**.
- In CI, rotate:
  - repo deploy keys
  - OIDC trust policies / short-lived credentials configs
  - package registry tokens

3) **Preserve evidence (lightweight)**
- Capture:
  - `package-lock.json` / `pnpm-lock.yaml` / `poetry.lock`
  - `npm ls --all` / `pip freeze` (as applicable)
  - install logs (CI logs, terminal scrollback)
  - the exact package tarball/wheel if available (cache, `.npm/_cacache`, pip download cache)
- Record timestamps and hostnames.

## Triage questions
- Did it run only at **install time** (postinstall scripts) or also at runtime?
- Did it run in **CI** with elevated permissions?
- Was it executed on a developer machine that has long-lived credentials?
- Was it present on build machines used for **release signing**?

## Containment & eradication
- Remove the package and revert lockfiles to a known-good state.
- If the package executed with meaningful privileges, prefer **reimaging** the host over “cleanup”.
- In CI: invalidate caches that may contain malicious artifacts.

## Hunt & validation
- Look for:
  - unexpected outbound connections during install/build/test
  - persistence mechanisms (cron, systemd units, launch agents)
  - new SSH keys, modified shell profiles, suspicious binaries in temp dirs
  - tampered build outputs (supply chain backdoor risk)

## Recovery & prevention
- Enforce:
  - lockfile pinning in CI
  - allowlisted registries + scoped tokens
  - dependency review gates for new packages/versions
  - sandboxed builds with minimal egress
  - signing/attestation for internal artifacts

## References
- GitHub Advisory example (malicious npm package; guidance: treat host as compromised, rotate secrets):
  - https://github.com/advisories/GHSA-2f47-cw56-c2fv
