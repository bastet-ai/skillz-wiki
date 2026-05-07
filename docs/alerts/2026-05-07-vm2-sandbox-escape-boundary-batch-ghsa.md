# vm2 sandbox-escape boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** vm2 batch where multiple JavaScript sandbox assumptions again crossed into host process access.

## Advisories covered

- **Promise constructor unhandled-rejection escape / process-crash DoS** — [GHSA-hw58-p9xv-2mjh](https://github.com/advisories/GHSA-hw58-p9xv-2mjh)
- **NodeVM builtin allowlist bypass through `module` / `Module._load`** — [GHSA-947f-4v7f-x2v8](https://github.com/advisories/GHSA-947f-4v7f-x2v8)
- **Mutable proxies for host intrinsic prototypes** — [GHSA-vwrp-x96c-mhwq](https://github.com/advisories/GHSA-vwrp-x96c-mhwq)
- **Host object access enabling sandbox escape** — [GHSA-47x8-96vw-5wg6](https://github.com/advisories/GHSA-47x8-96vw-5wg6)
- **Additional sandbox escape path** — [GHSA-qcp4-v2jj-fjx8](https://github.com/advisories/GHSA-qcp4-v2jj-fjx8)
- **NodeVM `nesting: true` bypass of `require: false`** — [GHSA-8hg8-63c5-gwmx](https://github.com/advisories/GHSA-8hg8-63c5-gwmx): sandbox code can re-import `vm2`, create a nested `NodeVM`, and regain host command execution when nesting is enabled.
- **NodeVM `require.root` symlink traversal** — [GHSA-cp6g-6699-wx9c](https://github.com/advisories/GHSA-cp6g-6699-wx9c): path checks use resolved strings while module loading follows symlinks, letting linked workspaces escape allowed roots.
- **Transformer fast-path internal-state exposure** — [GHSA-wp5r-2gw5-m7q7](https://github.com/advisories/GHSA-wp5r-2gw5-m7q7): keyword-based AST skipping can miss internal security-state identifiers.
- **Host path disclosure through stack traces** — [GHSA-v27g-jcqj-v8rw](https://github.com/advisories/GHSA-v27g-jcqj-v8rw): CallSite wrappers can expose absolute host paths, framework layout, and package versions.
- **Host Promise object-identity leakage** — [GHSA-mpf8-4hx2-7cjg](https://github.com/advisories/GHSA-mpf8-4hx2-7cjg): host objects resolved through Promises can cross the bridge without full proxy conversion.
- **`Buffer.alloc()` timeout bypass / host OOM** — [GHSA-6785-pvv7-mvg7](https://github.com/advisories/GHSA-6785-pvv7-mvg7): synchronous native allocation is not interrupted by vm2's JavaScript timeout guard.

## Why this is durable

In-process JavaScript sandboxes are not a hard tenant or attacker boundary. vm2 bugs repeatedly appear at seams where the guest can reach host constructors, intrinsic prototypes, module loading, exception handling, path resolution, Promise bridging, stack metadata, native allocation, or proxy wrappers. Treat every new escape as another reminder that language-level isolation should be backed by OS/process isolation.

## Immediate triage

1. Inventory every service, CI job, plugin runner, template engine, agent tool, or user automation path that evaluates untrusted JavaScript through vm2 or NodeVM.
2. Patch to the newest fixed vm2 line where a maintained fix exists; for this batch, treat **3.11.1+** as the minimum target where `NodeVM nesting` is in use, and disable the feature or move execution out of process if a fixed version is not deployable.
3. Treat exposed multi-tenant vm2 workloads as potentially compromised: review child process, file, network, credential, package-manager, and webhook activity from the host account.
4. Remove ambient secrets from the Node process that hosts the sandbox. Use short-lived, task-scoped credentials delivered only after policy checks.
5. Add regression tests for host constructor access, `module` loading, nested `NodeVM`, symlinked `require.root`, proxy unwraps, Promise species/constructor paths, host Promise resolution, stack-trace metadata, native allocation limits, and unhandled exception channels.

## Durable controls

- Run untrusted code in a separate container, VM, microVM, or locked-down worker process with seccomp/AppArmor, memory/cpu cgroups, read-only filesystems, no package-manager write access, and explicit egress policy.
- Make sandbox escape a contained workload compromise, not an application-server compromise.
- Keep an emergency kill switch for user-supplied script execution and plugin marketplaces.
- Log sandbox task identity, tenant, input digest, network attempts, filesystem writes, module loads, symlinked dependency roots, allocation failures/OOM kills, and child-process attempts for incident reconstruction.
