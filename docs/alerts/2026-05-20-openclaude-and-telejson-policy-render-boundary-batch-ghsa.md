# OpenClaude and TeleJSON policy/render-boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-20.

This batch is durable because both advisories show untrusted data crossing into code or policy execution: model-controlled tool input disabling an agent sandbox, and attacker-controlled serialized JSON shaping a JavaScript constructor through `new Function()`.

## What changed

- **OpenClaude sandbox bypass via model-controlled `dangerouslyDisableSandbox` input** — [GHSA-m77w-p5jj-xmhg](https://github.com/advisories/GHSA-m77w-p5jj-xmhg): vulnerable `openclaude <0.5.1` exposed `dangerouslyDisableSandbox` in the BashTool input schema. With the default `allowUnsandboxedCommands: true`, a prompt-injected or compromised model could set that flag in a tool call and force arbitrary commands to run outside the sandbox. This refresh confirms the critical agent-policy boundary issue remains worth tracking even though the first local note already covered the pattern.
- **TeleJSON DOM XSS through constructor-name deserialization** — [GHSA-ccgf-5rwj-j3hv](https://github.com/advisories/GHSA-ccgf-5rwj-j3hv): vulnerable `telejson <6.0.0` passed attacker-controlled `_constructor-name_` values from parsed JSON into `new Function()` while reconstructing prototypes. Applications that parse untrusted TeleJSON payloads, including cross-frame or `postMessage` style data paths, can turn serialized data into JavaScript execution.

## Operator triage

1. Upgrade `openclaude` to `0.5.1` or later and `telejson` to `6.0.0` or later anywhere they are packaged into developer tools, internal consoles, Storybook-adjacent UI tooling, or agent runtimes.
2. Audit recent OpenClaude runs for commands that would only be possible without sandboxing: writes outside the workspace, unexpected network calls, credential-file access, shell persistence, or tool configuration changes.
3. Search code for `dangerouslyDisableSandbox`, `allowUnsandboxedCommands`, `telejson.parse`, `_constructor-name_`, and `postMessage` handlers that pass received data directly into TeleJSON.
4. Treat any browser session that parsed untrusted TeleJSON with vulnerable versions as potentially script-compromised; rotate tokens exposed to that origin/session.

## Replayable validation boundaries

- **Agent policy immutability test:** force a model/tool response to include `"dangerouslyDisableSandbox": true`; expected result is rejection or ignored input unless an operator-owned, out-of-band policy explicitly allowed unsandboxed execution for that command.
- **Sandbox default test:** boot a clean OpenClaude config and inspect effective policy; expected result is sandbox-on and unsandboxed commands denied by default, not enabled through absent config.
- **TeleJSON constructor injection test:** feed a crafted `_constructor-name_` payload to any untrusted parser path in a test browser; expected result is inert data or parse rejection, never `new Function()` execution.
- **Cross-frame trust test:** send malformed TeleJSON over `postMessage` from an untrusted origin; expected result is origin validation before parse and safe failure on unexpected schema.

## Durable controls

- Keep sandbox posture, network mode, writable roots, and tool allowlists outside model-controllable schemas. If a field can relax execution policy, it belongs in operator config, not tool-call input.
- Deny unsandboxed execution by default; require explicit human/operator approval and durable audit logs for every escape hatch.
- Avoid `new Function()` or dynamic constructor reconstruction while deserializing attacker-controlled data. If object restoration is required, use an allowlist of known type tags mapped to safe constructors.
- Validate message origin, schema, and version before parsing cross-window or plugin data; parse into plain objects first, then hydrate only after authorization.
- Add regression tests for prompt-injected sandbox flags and serialized constructor-name payloads so policy and render boundaries cannot silently regress.
