# Debug mode is not a feature (disable debuggers reliably)

Framework “debug mode” is often **remote code execution** waiting to happen. Treat it like a production outage: it must be **provably off**, not “probably off”.

This guidance was triggered by a class of bugs where configuration values are parsed as **strings** and passed to a boolean parameter (e.g., `debug="False"` → truthy → debug stays on).

## What goes wrong (common failure mode)

- Config files / env vars are strings (`"False"`, `"0"`, `"no"`).
- Code passes the string directly into a boolean parameter.
- In many languages, **any non-empty string is truthy**, so debug turns on.

Example (Python):

```py
# BAD: debug is a string
unfurl_debug = config["APP"].get("debug", "True")
app.run(debug=unfurl_debug)  # "False" is truthy
```

## Defender checks (high leverage)

### 1) Block debug endpoints at the edge

If your stack exposes debug UIs (Werkzeug debugger, Spring actuator, Django debug pages):

- Denylist known paths in your reverse proxy/WAF.
- Require authentication + IP allowlisting for admin-only endpoints.

### 2) Detect it from the outside (smoke test)

Add a CI/CD or synthetic check that:

- Requests a known error path.
- Fails the deploy if the response contains debugger fingerprints (e.g., “Werkzeug Debugger”, stack traces with interactive console affordances).

### 3) Make “debug off” the default

- Production should default to `debug = False`.
- Require an explicit, *development-only* flag to turn it on.

### 4) Parse booleans explicitly (don’t rely on truthiness)

- Python: `configparser.ConfigParser().getboolean(...)` (or strict parsing helper)
- Node: parse env vars to booleans (`process.env.DEBUG === "true"`)
- Go: `strconv.ParseBool`

If the value is invalid, **fail closed** (treat as `false` and log loudly).

## Incident response note

If you discover debug mode was exposed:

- Assume **secrets leaked** (cookies, env vars, stack traces, internal URLs).
- Rotate credentials/tokens that could have been displayed.
- Review access logs for requests to debug endpoints and exception-triggering paths.

## References

- GitHub Security Advisory feed: Unfurl debug mode string parsing (Werkzeug debugger exposure) (2026-01-29)

## October 23 2026 follow-up: AgenticSeek — hardcoded debug on a public bind, and the Werkzeug PIN as a derivable gate ([GHSA-r5cp-9ffr-m5mf](https://github.com/advisories/GHSA-r5cp-9ffr-m5mf) / CVE-2026-115727, critical, CVSS 8.1, before commit 409840c)

`llm_server/app.py` hardcoded Flask `debug=True` while binding to all interfaces. Reaching the server port plus obtaining the **derivable** Werkzeug debugger PIN = Python code and OS command execution with the llm_server privileges. The AI-agent serving stack keeps reproducing this exact shape: an agent/LLM server component booted with the framework debug flag on, on `0.0.0.0`, in deployments that assume network ACLs are the auth.

Operator rules (authorized testing only):

- **A debugger on a non-loopback bind is the whole finding.** When fingerprinting agent/LLM/dev servers, check every discovered Flask/Werkzeug (or equivalent REPL-console) surface for the interactive-console affordance before testing app auth — the console is a pre-auth code-exec surface if the gate is only the PIN.
- **The Werkzeug PIN is an access gate, not a secret.** It is derived from machine-visible identifiers (MAC address, machine-id) plus per-instance values the console itself discloses; the derivation is publicly documented. Treat "the PIN protects it" as fail-open once the server is reachable: harvest the values the PIN formula consumes from disclosures you already have, then verify interactively in lab. Do not publish or share PIN generator output against third-party hosts.
- **Config-string truthiness remains the audit grep** (`debug="False"`, env-sourced flags passed straight into boolean parameters) — but note this leg didn't even need a parse bug: the flag was hardcoded. Grep agent-serving repos for `debug=True`, `FLASK_DEBUG`, and `host="0.0.0.0"` co-occurrence in the same app file; that pair is the fingerprint.
- Same-wave sibling tracked: Electron SameSite restrictions not applied to link-opened windows ([GHSA-2p8c-gr87-2676](https://github.com/advisories/GHSA-2p8c-gr87-2676) / CVE-2026-113796) — cookie-scope parity across window-creation paths, known transport-parity class.
