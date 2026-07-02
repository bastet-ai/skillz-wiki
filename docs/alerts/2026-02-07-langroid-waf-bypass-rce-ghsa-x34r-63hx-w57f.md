# Langroid `TableChatAgent` WAF-bypass boundary check

GitHub advisory: <https://github.com/advisories/GHSA-x34r-63hx-w57f> / CVE-2026-25481.

GitHub Advisory Database refreshed this item on 2026-07-01. The durable operator lesson is not the public proof string itself; it is the recurring boundary where an LLM table assistant exposes a dataframe expression engine, wraps it in a WAF-like filter, and still leaves Python object capabilities reachable through method chains and dunder/global access.

## Why operators should care

`TableChatAgent` can call a `pandas_eval` capability against a DataFrame. Langroid added filtering after the earlier `TableChatAgent` eval issue, but affected versions `<= 0.59.31` could still be driven from allowed dataframe operations into dangerous Python reflection surfaces such as dunder attributes, `__globals__`, builtins, or equivalent object-capability paths.

Prioritize this when a target:

- exposes `TableChatAgent`, CSV/dataframe chat, BI copilots, notebook helpers, or support analytics bots to untrusted or semi-trusted prompts;
- lets retrieved web/user content influence the table agent indirectly;
- runs the agent near notebooks, datasets, service credentials, CI/CD tokens, cloud metadata, or internal network routes;
- upgraded only to the first sanitizer but has not confirmed `langroid >= 0.59.32`.

## Safe validation path

1. Confirm package evidence for `langroid <= 0.59.31` and that `TableChatAgent` or `pandas_eval` is reachable from user-controlled prompts, files, or retrieved content.
2. Establish a benign dataframe expression that should be allowed and record the normal tool-call path.
3. In an isolated lab, test whether an expression can leave the intended dataframe/query language and reach Python object capabilities. Use an inert marker such as printing a fixed string or writing to a disposable temp file.
4. For production or bug-bounty environments, stop at source/version plus expression-construction evidence unless the program explicitly allows code-execution validation. Do not list directories, read files, access cloud metadata, query real datasets, or spawn shells.
5. Compare against `langroid >= 0.59.32`, where the bypass chain should be rejected.

## Evidence to capture

- Langroid version and the exact agent/tool configuration.
- Whether the prompt path is direct user input, uploaded data, RAG content, or an internal-only operator console.
- The allowed dataframe operation, the attempted object-capability escape class, and the inert marker result.
- Patched-version or disabled-tool negative control.
- A clear statement of host privileges and reachable data categories without collecting secrets.

## Reporting heuristic

Lead with the crossed boundary: **untrusted prompt or retrieved content to dataframe expression sandbox escape**. Strong reports show that the application relies on `TableChatAgent` filtering as a security boundary, that the model/tool path is reachable by the attacker, and that an inert capability escape is possible in a controlled environment.

Keep the proof bounded. This page is for authorized validation, not for publishing payloads that read files, exfiltrate credentials, call metadata endpoints, or run production commands.
