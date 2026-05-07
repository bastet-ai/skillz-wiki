# vm2 sandbox-escape boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** vm2 batch where multiple JavaScript sandbox assumptions again crossed into host process access.

## Advisories covered

- **Promise constructor unhandled-rejection escape / process-crash DoS** — [GHSA-hw58-p9xv-2mjh](https://github.com/advisories/GHSA-hw58-p9xv-2mjh)
- **NodeVM builtin allowlist bypass through `module` / `Module._load`** — [GHSA-947f-4v7f-x2v8](https://github.com/advisories/GHSA-947f-4v7f-x2v8)
- **Mutable proxies for host intrinsic prototypes** — [GHSA-vwrp-x96c-mhwq](https://github.com/advisories/GHSA-vwrp-x96c-mhwq)
- **Host object access enabling sandbox escape** — [GHSA-47x8-96vw-5wg6](https://github.com/advisories/GHSA-47x8-96vw-5wg6)
- **Additional sandbox escape path** — [GHSA-qcp4-v2jj-fjx8](https://github.com/advisories/GHSA-qcp4-v2jj-fjx8)

## Why this is durable

In-process JavaScript sandboxes are not a hard tenant or attacker boundary. vm2 bugs repeatedly appear at seams where the guest can reach host constructors, intrinsic prototypes, module loading, exception handling, or proxy wrappers. Treat every new escape as another reminder that language-level isolation should be backed by OS/process isolation.

## Immediate triage

1. Inventory every service, CI job, plugin runner, template engine, agent tool, or user automation path that evaluates untrusted JavaScript through vm2 or NodeVM.
2. Patch to the newest fixed vm2 line where a maintained fix exists; if no fix is available for a specific path, disable the feature or move execution out of process.
3. Treat exposed multi-tenant vm2 workloads as potentially compromised: review child process, file, network, credential, package-manager, and webhook activity from the host account.
4. Remove ambient secrets from the Node process that hosts the sandbox. Use short-lived, task-scoped credentials delivered only after policy checks.
5. Add regression tests for host constructor access, `module` loading, proxy unwraps, Promise species/constructor paths, and unhandled exception channels.

## Durable controls

- Run untrusted code in a separate container, VM, microVM, or locked-down worker process with seccomp/AppArmor, read-only filesystems, no package-manager write access, and explicit egress policy.
- Make sandbox escape a contained workload compromise, not an application-server compromise.
- Keep an emergency kill switch for user-supplied script execution and plugin marketplaces.
- Log sandbox task identity, tenant, input digest, network attempts, filesystem writes, and child-process attempts for incident reconstruction.
