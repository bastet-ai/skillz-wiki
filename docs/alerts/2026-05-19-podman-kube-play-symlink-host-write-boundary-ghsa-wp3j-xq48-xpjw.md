# Podman `kube play` symlink host-write boundary (GHSA-wp3j-xq48-xpjw)

Source: GitHub Security Advisories updated 2026-05-19.

## Signal

`GHSA-wp3j-xq48-xpjw` / `CVE-2025-9566` describes a high-severity Podman `kube play` flaw: when `kube play` uses ConfigMap or Secret volume mounts and the same volume is started more than once, a container can plant a symlink during the first run. Later `kube play` runs may follow that symlink while writing ConfigMap/Secret data, overwriting a host file path chosen by the attacker. The attacker controls the target path, while the bytes written come from the operator-supplied YAML.

Affected ranges listed by GitHub:

- `github.com/containers/podman/v5 <= 5.6.0`; fixed in `5.6.1`.
- `github.com/containers/podman/v4 <= 4.9.5`; no first patched v4 version listed in the advisory.

## Why it matters

Container orchestration helpers often treat ConfigMaps, Secrets, and existing volumes as administrative plumbing. This bug is durable because it crosses three boundaries at once: untrusted container filesystem state, operator-supplied Kubernetes YAML, and host filesystem writes. A local or workload-level actor does not need to choose the file contents to cause damage; forcing trusted Secret or ConfigMap content into a sensitive host path can still break service integrity, corrupt config, or create an availability incident.

## Triage

1. Inventory systems where Podman `kube play` runs Kubernetes YAML with ConfigMap or Secret volume mounts, especially recurring jobs, lab automation, CI runners, and developer workstations.
2. Upgrade Podman v5 deployments to `5.6.1` or later. Treat v4 deployments as requiring vendor/backport confirmation or workflow removal until fixed packages are verified.
3. Avoid `podman kube play` with ConfigMap or Secret volume mounts on untrusted or reused volumes until patched.
4. Inspect reused Podman volumes touched by untrusted containers for symlinks and hardlinks before replaying YAML.
5. Hunt for unexpected host file mtimes or contents after repeated `kube play` starts, especially files plausibly targeted by symlink paths such as service configs, authorized keys, cron/systemd fragments, app config, or writable host paths.

## Defensive pattern

- Treat volumes reused across container starts as attacker-controlled state, not as a clean deployment target.
- Before writing ConfigMap, Secret, archive, or copy payloads into a volume, resolve the final path from a trusted directory descriptor and reject symlinks, hardlinks, device files, absolute paths, and parent traversal.
- Prefer fresh, private deployment volumes for each untrusted run; if reuse is required, scrub or recreate them from trusted state.
- Keep orchestration helpers least-privileged: avoid running container-to-host file population paths with broader host write permission than needed.

## References

- <https://github.com/advisories/GHSA-wp3j-xq48-xpjw>
- <https://github.com/containers/podman/security/advisories/GHSA-wp3j-xq48-xpjw>
- <https://github.com/containers/podman/commit/43fbde4e665fe6cee6921868f04b7ccd3de5ad89>
