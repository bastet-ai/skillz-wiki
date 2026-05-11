# Sandbox, Git, and Kubernetes execution-boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11 16:15-16:21 UTC.

This batch is durable because it shows how “helper” execution paths become real RCE boundaries: expression filters, custom guardrail code, Git discovery, and Kubernetes helper pod templates all need a positive policy model before they touch a host or privileged process.

## Advisories covered

- **Angular Expressions filter sandbox escape** — [GHSA-pw8r-6689-xvf4](https://github.com/advisories/GHSA-pw8r-6689-xvf4) / CVE-2026-44643: malicious expressions could use filter handling, including `__proto__`-style paths, to escape the intended sandbox and execute arbitrary code. Affects `angular-expressions <=1.5.1`; fixed in 1.5.2.
- **LiteLLM custom-code guardrail sandbox escape** — [GHSA-wxxx-gvqv-xp7p](https://github.com/advisories/GHSA-wxxx-gvqv-xp7p) / CVE-2026-40217: `POST /guardrails/test_custom_code` ran user-supplied Python in a hand-rolled sandbox that could be escaped with bytecode techniques, executing in the proxy process and root by default Docker image. Requires proxy-admin credentials in default configurations. Affects `litellm >=1.81.8,<1.83.10`; fixed in 1.83.11. [GHSA-3926-2jvf-fg29](https://github.com/advisories/GHSA-3926-2jvf-fg29) is the withdrawn duplicate.
- **GitHub Copilot CLI nested bare repository execution** — [GHSA-9ccr-r5hg-74gf](https://github.com/advisories/GHSA-9ccr-r5hg-74gf) / CVE-2026-45033: a malicious bare Git repository nested inside a project could be auto-discovered during Git traversal and use config keys such as `core.fsmonitor`, `core.hookspath`, `diff.external`, or merge tools to execute commands. Affects `@github/copilot <=1.0.42`.
- **Rancher Local Path Provisioner helperPod template injection** — [GHSA-7fxv-8wr2-mfc4](https://github.com/advisories/GHSA-7fxv-8wr2-mfc4) / CVE-2026-44543: users able to edit `local-path-config` could inject privileged security contexts, hostPath mounts, or Linux capabilities into `helperPod.yaml`, causing host access when PVC provisioning/cleanup created helper pods. Affects `github.com/rancher/local-path-provisioner <0.0.36`.

## Operator triage

1. Patch Angular Expressions to 1.5.2+, LiteLLM to 1.83.11+, Copilot CLI beyond 1.0.42, and Local Path Provisioner to 0.0.36+.
2. Block or disable LiteLLM `POST /guardrails/test_custom_code` at the gateway until upgraded; do not rely on proxy-admin scope as the only containment when the proxy runs as root.
3. Treat AI/code-agent workspaces as hostile: set Git safe-directory policy, disable automatic traversal into untrusted nested bare repositories, and scan repositories for bare `.git` directories plus executable config keys before agent activity.
4. Restrict write access to `local-path-config` to a tiny storage-admin group; admission-control HelperPods so `privileged`, host-root `hostPath`, and extra capabilities cannot be introduced by templates.
5. Inventory expression-template usage and ban untrusted expression evaluation unless it runs in an OS/container sandbox with no filesystem, network, or process privileges.

## Durable controls

- Hand-rolled language sandboxes are brittle; put untrusted code in a separate process/container/VM with a deny-by-default seccomp/AppArmor/network/filesystem profile.
- Git config is executable configuration. Agents and CLIs must treat repository discovery as code execution, not passive metadata reading.
- Kubernetes templates are privilege-bearing inputs. Validate rendered pod specs against policy, not just the source ConfigMap shape.
- “Admin-only” test endpoints still need production-grade isolation, because stolen admin tokens turn diagnostics into execution surfaces.
