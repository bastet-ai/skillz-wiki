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

## July 2 Langroid SQL and file-tool boundary follow-up

GitHub Advisory Database published two adjacent Langroid issues on 2026-07-02: [GHSA-pmch-g965-grmr](https://github.com/advisories/GHSA-pmch-g965-grmr) / CVE-2026-50180 for `SQLChatAgent` `_validate_query` blocklist gaps, and [GHSA-fg23-3346-88f5](https://github.com/advisories/GHSA-fg23-3346-88f5) / CVE-2026-50181 for `ReadFileTool` / `WriteFileTool` traversal outside `curr_dir`. Both affect `langroid <= 0.63.0` and extend the same operator lesson: LLM tool guardrails are security boundaries only if final SQL, file paths, and filesystem effects are constrained after model/tool generation.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-pmch-g965-grmr](https://github.com/advisories/GHSA-pmch-g965-grmr) / CVE-2026-50180 | `SQLChatAgent.run_query` and `_validate_query` | prompt-shaped `SELECT` queries can reach PostgreSQL filesystem-disclosure functions such as `pg_read_file()` or adjacent SQL Server/SQLite file primitives despite `allow_dangerous_operations=False` | Test SQL agents against dialect-specific file and extension functions, not just statement-type allowlists or generic dangerous-keyword filters. |
| [GHSA-fg23-3346-88f5](https://github.com/advisories/GHSA-fg23-3346-88f5) / CVE-2026-50181 | Langroid `ReadFileTool` and `WriteFileTool` | `curr_dir` changes the process working directory but does not enforce final realpath confinement, allowing `../` traversal reads/writes | Agent file tools need final-path containment checks; changing CWD is not a sandbox. |

### Safe validation additions

- Preconditions: isolated Langroid lab, `langroid <= 0.63.0`, synthetic database/filesystem canaries, least-privilege database role, empty temp workspace, and no production datasets or secrets.
- For `SQLChatAgent`, seed a disposable database with normal table data and configure a harmless canary file owned by the database service only in a lab. Shape the agent/tool call toward a `SELECT`-only filesystem function and record whether `_validate_query` permits it. Positive evidence can be a fixed marker string from the synthetic file or a blocked/allowed decision table; do not read `/etc/passwd`, credentials, logs, cloud metadata, or application data.
- For `ReadFileTool` / `WriteFileTool`, set `curr_dir` to a temp project directory and place a marker file in a sibling temp directory. Attempt only `../skillz-langroid-canary.txt`-style traversal. Positive evidence is marker read/write outside `curr_dir`; negative control is realpath rejection or a patched version.
- For both issues, include a negative control where the same prompt/tool call is rejected after final SQL function policy or final realpath containment is enforced.

### Additional reporting heuristic

Lead with the crossed boundary: **LLM-generated SELECT to database-host file primitive** or **agent file tool path to outside-workspace read/write**. Strong reports show how untrusted prompt, RAG content, uploaded data, or delegated agent tasks can influence the final tool input while the application relies on Langroid guardrails for containment.

## July 6 Neo4jChatAgent Cypher boundary follow-up

GitHub Advisory Database published [GHSA-2pq5-3q89-j7cc](https://github.com/advisories/GHSA-2pq5-3q89-j7cc) / CVE-2026-55615 for Langroid `Neo4jChatAgent`, where LLM-generated Cypher can execute without sufficient validation and, depending on Neo4j configuration, may reach dangerous procedures or command-capable plugins.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-2pq5-3q89-j7cc](https://github.com/advisories/GHSA-2pq5-3q89-j7cc) | Langroid `Neo4jChatAgent` | prompt-shaped graph queries cross from natural language into Cypher execution without a final safe-query policy | Graph/LLM agents need dialect-aware query containment just like SQL/table agents; validate generated Cypher against allowed clauses, procedures, labels, and write/file/network capabilities. |

### Safe Neo4j agent validation additions

- Preconditions: isolated Langroid lab, disposable Neo4j instance with synthetic graph data, no APOC or command/file procedures unless explicitly part of the lab negative-control matrix, and no production datasets or secrets.
- Establish the normal natural-language-to-Cypher tool path using a benign read-only query over seeded marker nodes.
- Shape prompts or retrieved content toward a Cypher form that should be rejected by policy, such as write clauses, procedure calls, multi-statement behavior, or configuration-conditional dangerous procedures. Use parser/log evidence or inert marker nodes only.
- Positive evidence: the agent executes a query class outside the intended read-only graph-question boundary. If a dangerous procedure is enabled in a lab, stop at a fixed canary string or temp marker and document the enabling precondition.
- Negative controls: strict generated-query allowlist, procedure deny/allow policy, read-only database credentials, patched Langroid behavior, and a same prompt rejected before Neo4j execution.
- Report this as **untrusted prompt/RAG content to unconstrained Cypher execution**. Never read real graph data, run shell commands, access filesystem paths, or connect to production Neo4j plugins.

## July 6 raw tool JSON, TableChatAgent eval, and SQLChatAgent regex-bypass follow-up

Later July 6 GitHub Advisory Database entries add three adjacent Langroid tool-boundary cases: [GHSA-gjgq-w2m6-wr5q](https://github.com/advisories/GHSA-gjgq-w2m6-wr5q) / CVE-2026-54771 for direct user-supplied tool JSON reaching `handle_message()`, [GHSA-q9p7-wqxg-mrhc](https://github.com/advisories/GHSA-q9p7-wqxg-mrhc) / CVE-2026-54769 for `TableChatAgent` / `VectorStore` `full_eval=True` sandbox escape through implicit Python builtins, and [GHSA-6xc5-4r68-67fc](https://github.com/advisories/GHSA-6xc5-4r68-67fc) / CVE-2026-54760 for `SQLChatAgent` dangerous-function regex bypasses using quoted, commented, or schema-qualified PostgreSQL function names.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-gjgq-w2m6-wr5q](https://github.com/advisories/GHSA-gjgq-w2m6-wr5q) | Langroid `agent_response()` / `handle_message()` tool dispatch | raw user chat content can be parsed as tool JSON even when a tool is configured `use=False, handle=True` | Agent reviews must verify tool-call origin and sender identity, not only whether the LLM is allowed to generate a tool call. |
| [GHSA-q9p7-wqxg-mrhc](https://github.com/advisories/GHSA-q9p7-wqxg-mrhc) | `TableChatAgent` and `VectorStore` with `full_eval=True` | generated Python evaluation can receive implicit `__builtins__` and escape the intended dataframe/vector expression sandbox | Eval sandboxes need explicit global and builtin removal plus process isolation; empty locals alone is not containment. |
| [GHSA-6xc5-4r68-67fc](https://github.com/advisories/GHSA-6xc5-4r68-67fc) | `SQLChatAgent` `_validate_query` | blocklist regexes miss equivalent PostgreSQL callable syntax such as quoted identifiers, comments before `(`, or schema-qualified functions | SQL-agent validation must parse and classify final AST/function calls, not rely on raw-text regex matches. |

### Safe validation additions

- Preconditions: isolated Langroid lab, affected versions, no production tools, no real database files, synthetic chat users, disposable dataframe/vector data, and least-privilege scratch PostgreSQL only when testing SQL.
- For raw tool JSON, register an inert test tool with `use=False, handle=True` that returns only a fixed marker. Send the JSON as a user message and record whether the handler runs despite the sender being `Entity.USER`. Negative control: dispatcher rejects user-originated tool messages unless the tool is explicitly user-callable.
- For `full_eval=True`, use only a marker expression in a disposable process to prove whether builtins are present. Stop at a fixed string or temp marker; do not run shells, import network clients, read files, or access environment variables.
- For `SQLChatAgent`, build a decision table of equivalent PostgreSQL function-call spellings against a synthetic file or mocked query logger. Positive evidence can be validator acceptance or generated-query logs; do not read `/etc/passwd`, database config, cloud metadata, logs, or customer data.
- Negative controls: final tool-call origin checks, explicit `__builtins__={}` plus sandboxed subprocesses where eval remains necessary, AST-based SQL function allowlists, read-only database credentials, and patched Langroid behavior.
- Report these as **user message to unauthorized tool handler**, **LLM output to Python eval builtins**, or **prompt-shaped SQL to parser-equivalent file function**. Include configuration flags, sender/source, final tool or query input, marker-only result, and fixed-version rejection.
