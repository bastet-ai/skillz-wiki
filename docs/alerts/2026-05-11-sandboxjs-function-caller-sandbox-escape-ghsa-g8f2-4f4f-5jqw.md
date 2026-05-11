# SandboxJS Function.caller sandbox-escape boundary

Source: GitHub Security Advisories REST fallback updated 2026-05-11 20:15 UTC.

This follow-up is durable because JavaScript sandboxes repeatedly fail when the sandboxed language can observe host call frames or constructors. The new SandboxJS advisory is another reminder that a denylist around dynamic code execution is not a containment boundary if guest code can reach host internals through reflection.

## Advisory covered

- **SandboxJS has a sandbox escape via Function.caller leakage of internal call op** — [GHSA-g8f2-4f4f-5jqw](https://github.com/advisories/GHSA-g8f2-4f4f-5jqw), CVE-2026-43898 (Critical): npm `@nyariv/sandboxjs` <= 0.9.5; fixed in `0.9.6`.

## Operator triage

1. Upgrade `@nyariv/sandboxjs` to **0.9.6+** anywhere it evaluates user-authored expressions, workflow formulas, rules, plugins, or AI-generated snippets.
2. Search for SandboxJS usage in web apps, automation tools, notebooks, and server-side customization layers. Prioritize deployments where untrusted users can submit code and the host process has secrets or filesystem/network reachability.
3. Rotate tokens and inspect host logs if untrusted SandboxJS code ran before patching; a critical sandbox escape should be treated as possible host compromise, not merely application-level code execution.
4. If sandboxed code is required, move execution into an OS/process/container boundary with seccomp/AppArmor, read-only filesystem, no ambient credentials, no metadata access, egress filtering, and hard CPU/memory/time limits.

## Durable controls

- In-process JavaScript sandboxes are convenience features, not strong security boundaries. Reflection, prototypes, getters, `Function`, stack/caller exposure, async hooks, and host object membranes all need adversarial review.
- Never put production secrets, deploy keys, cloud credentials, or database superuser handles in the same process that evaluates tenant-controlled code.
- Treat “expression language” features as code execution. If users can write formulas, filters, transforms, or rules, they can often reach language edges that normal unit tests miss.
- Maintain a kill switch to disable custom-code execution quickly during advisory windows.

## Related Wisdom

- [SandboxJS sandbox escape TOCTOU](2026-02-05-sandboxjs-sandbox-escape-toctou-ghsa-7x3h-rm86-3342.md)
- [vm2 sandbox-escape boundary batch](2026-05-07-vm2-sandbox-escape-boundary-batch-ghsa.md)
- [Agent, sandbox, tool, and secret-boundary batch](2026-05-11-agent-sandbox-tool-and-secret-boundary-batch-ghsa.md)
