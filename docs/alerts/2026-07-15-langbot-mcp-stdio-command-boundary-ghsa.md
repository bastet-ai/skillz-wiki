# LangBot MCP STDIO command boundary checks

Source: hourly offensive-security scan, 2026-07-15 GitHub advisory wave. Primary entry: [GHSA-3pvh-63gf-j9mw](https://github.com/advisories/GHSA-3pvh-63gf-j9mw) / CVE-2026-54449.

This advisory is durable because it captures a recurring agent-platform boundary: an authenticated user can edit MCP server configuration, select a `STDIO` transport, and cause the application host to spawn the configured command through Model Context Protocol loader code. For operators, the reusable test is not the specific shell payload; it is whether user-controlled tool-server definitions cross from tenant/application settings into host process execution without a trust gate.

!!! warning "Authorized validation only"
    Keep proofs to disposable LangBot labs, lab-only users, inert commands such as marker-file writes inside a temporary directory or `printf` to a captured test log, and redacted configuration screenshots. Do not run reverse shells, exfiltrate environment variables, read host files, delete data, install persistence, or test production chatbot instances without explicit written approval.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-3pvh-63gf-j9mw](https://github.com/advisories/GHSA-3pvh-63gf-j9mw) / CVE-2026-54449 | LangBot MCP extension configuration | Authenticated users can add an MCP `STDIO` server whose command and arguments are passed to `StdioServerParameters` and executed as a subprocess on the LangBot host | Add agent extension/configuration paths to MCP command-execution testing, especially where any signed-in user can register local tool servers. |

## Replayable validation boundaries

1. Stand up a disposable LangBot lab at a vulnerable version such as `<= 4.10.5`, with one non-admin authenticated user if the product supports role separation.
2. Identify every route or UI workflow that can create or update MCP server definitions. Record whether the route is available to all authenticated users, workspace admins only, or global admins only.
3. Add a benign `STDIO` MCP server definition that runs an inert marker command. Prefer a command that writes a fixed marker under a lab temp directory owned by the LangBot process, or emits a marker string to a captured test log.
4. Trigger only the minimal tool-loading path needed for LangBot to initialize the MCP server.
5. Record whether the marker proves host-side subprocess execution under the LangBot service account.
6. Add controls for unauthenticated users, lower-privilege users if roles exist, patched or hardened builds, non-`STDIO` transports, command allowlists, disabled MCP extensions, and deployments where MCP config is restricted to trusted operators.

Report this as **authenticated MCP config write -> user-controlled STDIO server definition -> LangBot host subprocess execution**. Evidence should include role, route/UI path, config fields by class, marker command result, service-account context if safely observable, and negative controls. Avoid publishing reusable destructive payloads.

## Operator checklist

- [ ] Can any authenticated user create or update MCP server definitions?
- [ ] Does the product distinguish remote MCP transports from local `STDIO` transports?
- [ ] Are command and argument fields allowlisted, or are they passed directly to subprocess creation?
- [ ] Does tool loading happen immediately after save, at bot startup, or only when a user invokes a tool?
- [ ] Are MCP configurations scoped per tenant/workspace, or can one user modify global runtime config?
- [ ] Is there an audit trail showing who created the MCP server definition and when it executed?

## Reporting notes

- Lead with preconditions: authentication state, role, LangBot version, exposed MCP extension UI/API, whether sign-up is open, deployment network exposure, and service-account privilege.
- Prefer marker-only evidence: config diff, inert command class, marker file path under a temp lab directory, log line, and patched or disabled-MCP negative control.
- Redact session cookies, API keys, bot tokens, environment variables, hostnames from customer environments, and absolute paths outside disposable lab directories.
- The same scan included MLflow deterministic dataset-digest collisions, Protobuf recursion-depth denial of service, and Garmin OAuth token file-permission advisories. They were marked processed without promotion because this run did not identify a safe, durable offensive operator workflow beyond existing data-integrity, availability-exclusion, or local-secret-hygiene guidance.
