# AgentScope remote code injection in coding helpers (GHSA-cr24-fv3h-8cjm / CVE-2026-6603)

**Signal:** GitHub Security Advisories updated **2026-04-30**. AgentScope coding helpers were reported vulnerable to remotely triggerable code injection.

## What it is
AgentScope up to `1.0.18` exposes coding helper functions such as `execute_python_code` and `execute_shell_command` in `src/AgentScope/tool/_coding/_python.py`. The advisory reports that manipulation of these functions can cause code injection and that public exploit information exists. The advisory did not list a patched version when checked.

Affected package: pip `agentscope <= 1.0.18`.

Reference: <https://github.com/advisories/GHSA-cr24-fv3h-8cjm>

## Triage
1. Inventory AgentScope deployments, notebooks, demos, and agent services exposed to users, tenants, or external prompts.
2. Identify whether coding tools are registered in agents that process untrusted prompts, uploaded tasks, or remote workflow definitions.
3. Map runtime privileges: shell access, filesystem mounts, cloud credentials, Kubernetes service accounts, model/tool gateway tokens, and network reachability.
4. Preserve logs and workspace state if an exposed AgentScope service had coding helpers enabled.

## Mitigation
- Disable `execute_python_code`, `execute_shell_command`, and any equivalent coding tools for untrusted workflows until a fixed release or audited patch is deployed.
- Run agent coding tools only inside short-lived sandboxes with no ambient secrets, minimal filesystem mounts, and restricted egress.
- Require explicit human approval for shell/Python execution generated from prompts.
- Pin AgentScope versions and monitor upstream for a patched release or security advisory update.

## Detection ideas
- Hunt agent logs for tool calls that run shell metacharacters, network download/execution chains, credential discovery commands, or persistence attempts.
- Review filesystem changes in AgentScope workspaces after suspicious prompt sessions.
- Alert on AgentScope processes spawning shells, package managers, cloud CLIs, or outbound connections outside expected destinations.

## Durable lesson
Agent coding tools are remote execution surfaces when prompts or workflow definitions are attacker-controlled. Register them only in sandboxed, approval-gated contexts and assume prompt input can become process input.
