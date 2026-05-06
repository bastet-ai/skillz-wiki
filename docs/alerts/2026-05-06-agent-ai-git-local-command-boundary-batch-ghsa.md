# Agent, AI, Git, and local-command boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced agent, AI, Git, MCP, notebook, code-generation, and OpenClaw boundary failures updated on **2026-05-06**.

## Advisories covered

- **PraisonAI unauthenticated RCE and SSRF bypass** — [GHSA-xcmw-grxf-wjhj](https://github.com/advisories/GHSA-xcmw-grxf-wjhj), [GHSA-q9pw-vmhh-384g](https://github.com/advisories/GHSA-q9pw-vmhh-384g): tool override and fetch controls could be bypassed.
- **Hugging Face Smolagents injection** — [GHSA-54fq-v6x8-244g](https://github.com/advisories/GHSA-54fq-v6x8-244g): model/agent instruction data could cross into execution decisions.
- **GitPython config newline injection RCE** — [GHSA-v87r-6q3f-2j67](https://github.com/advisories/GHSA-v87r-6q3f-2j67): `config_writer().set_value()` could inject new config entries such as `core.hooksPath`.
- **rmcp DNS rebinding** — [GHSA-89vp-x53w-74fx](https://github.com/advisories/GHSA-89vp-x53w-74fx): Streamable HTTP server transport needed Host/origin binding.
- **JupyterLab one-click command execution** — [GHSA-mqcg-5x36-vfcg](https://github.com/advisories/GHSA-mqcg-5x36-vfcg): command-linker attributes in untrusted HTML could trigger commands.
- **Kiota code-generation literal injection** — [GHSA-2hx3-vp6r-mg3f](https://github.com/advisories/GHSA-2hx3-vp6r-mg3f): generated code needed literal-safe emission boundaries.
- **Duplicate OpenClaw Feishu file-read advisory** — [GHSA-qp56-gp47-jwj3](https://github.com/advisories/GHSA-qp56-gp47-jwj3): keep duplicate advisories mapped to the original file-sandbox control.
- **OpenClaw Tlon media disk exhaustion** — [GHSA-4g5x-2jfc-xm98](https://github.com/advisories/GHSA-4g5x-2jfc-xm98): media downloads could bypass core safety limits.
- **OpenClaw exec allowlist and mirror-sync escapes** — [GHSA-wpc6-37g7-8q4w](https://github.com/advisories/GHSA-wpc6-37g7-8q4w), [GHSA-cwf8-44x6-32c2](https://github.com/advisories/GHSA-cwf8-44x6-32c2): shell init-file options and unrestricted sync plus symlink traversal could defeat sandbox assumptions.

## Why this is durable

Agent systems make untrusted text, files, generated code, and local tools adjacent to authority. The durable rule is boring but vital: model output and repository content can request actions, but only a policy layer with canonical paths, literal encoders, egress checks, and bounded resources can grant them.

## Immediate triage

1. Patch PraisonAI, GitPython, rmcp, JupyterLab, Kiota, and OpenClaw components where affected; isolate unfixed agent runtimes from secrets and internal network egress.
2. Hunt for suspicious Git config writes involving embedded newlines, `core.hooksPath`, or repository-local hooks after automation ran.
3. Disable command-linker style HTML actions in notebook content unless the content is trusted and user-confirmed.
4. Enforce DNS rebinding defenses for localhost/control servers: Host allowlists, Origin checks, loopback binding, and per-session tokens.
5. For OpenClaw-like runtimes, apply shell option normalization, symlink-safe copy/sync, media byte/quota limits, and final realpath containment checks.

## Durable controls

- Treat generated code and config as compiler output: escape literals mechanically and test with delimiter/newline payloads.
- Require a second, non-model policy decision before executing tools, writing files, syncing directories, or fetching URLs.
- Revalidate canonical path and network destination after every redirect, symlink, archive extraction, and file-system boundary crossing.
- Track duplicate advisories by root control to avoid noisy rework while preserving detection coverage.
