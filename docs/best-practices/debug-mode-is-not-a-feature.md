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
