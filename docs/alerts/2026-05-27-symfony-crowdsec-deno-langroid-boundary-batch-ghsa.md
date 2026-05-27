# Symfony, CrowdSec, Deno, and Langroid boundary batch (GHSA, 2026-05-27)

**Signal:** GitHub Advisory Database published a late May 27 batch with durable offensive-operator value across sanitizer URL parsing, WAF body parsing, transport security assumptions, and LLM-to-database tool execution.

Promoted items:

- `GHSA-qc95-4862-92fh` / `CVE-2026-45066`: Symfony `html-sanitizer` host/scheme allowlist bypasses through RFC3986-vs-WHATWG URL parser differentials and `<area href>` being checked as media instead of a navigable link.
- `GHSA-h5vq-qfcg-4m6p` / `CVE-2026-45064`: Symfony `html-sanitizer` allows explicit Unicode BiDi control characters in URL attributes, creating visual destination-spoofing opportunities in sanitized content.
- `GHSA-rw47-hm26-6wr7` / `CVE-2026-44982`: CrowdSec AppSec drops request bodies when `Content-Length` is non-positive, including chunked HTTP/1.1 and HTTP/2 body framing without a `content-length`, causing body-targeted WAF rules to evaluate an empty body.
- `GHSA-chqv-56wv-7564` / `CVE-2026-44726`: Deno `node:tls` / `node:https` compatibility can send application data in plaintext after an address-family retry when callers write before `secureConnect`.
- `GHSA-mxfr-6hcw-j9rq` / `CVE-2026-25879`: Langroid `SQLChatAgent` before `0.63.0` can execute LLM-produced SQL; prompt injection can become database-host RCE when the configured database role exposes dialect-specific execution or file primitives.

Use this only in authorized tests. Keep proof minimal: demonstrate parser, framing, or privilege-boundary failure with harmless markers, then stop before data access, service disruption, or production command execution unless the program explicitly authorizes deeper validation.

## Operator checklist

### 1. Symfony `html-sanitizer` URL allowlist and visual-spoofing probes

Where to look:

- Composer projects using `symfony/html-sanitizer` or full `symfony/symfony` versions `>= 6.1.0, < 6.4.40`, `>= 7.0.0, < 7.4.12`, or `>= 8.0.0, < 8.0.12`.
- Rich-text editors, profile fields, comments, CMS blocks, support macros, email/template previews, and any stored HTML surface that claims to restrict links or media with `allowLinkHosts()`, `allowLinkSchemes()`, `allowMediaHosts()`, or `allowMediaSchemes()`.
- Sanitizer configurations that treat media and link policies differently; `<area href>` is especially interesting when media hosts/schemes are broader than link hosts/schemes.

Safe validation path:

1. Confirm sanitizer package and version through `composer.lock`, SBOMs, debug headers, dependency manifests, or vendor-provided version evidence.
2. Find a low-impact stored or preview-only HTML field where you can render sanitized content in your own account.
3. Test whether the sanitizer preserves an off-allowlist navigable destination when the server-side parser and browser disagree, for example the documented backslash and slash-count patterns, while using a harmless collector you control.
4. Test whether `<area href>` follows the stricter link policy or the looser media policy by placing it inside a minimal image map and observing the sanitized output.
5. For BiDi spoofing, use visible canary text and a destination you own. Capture a screenshot of the mismatch between the displayed URL/order and the actual attribute value; do not phish real users.

Evidence to capture:

- Sanitizer version and the exact allowlist configuration if observable.
- The raw submitted HTML and the sanitized output.
- Browser navigation result for the ambiguous URL form.
- Whether the issue is stored, reflected, preview-only, authenticated, or reachable by untrusted content authors.

Reporting heuristic: strong reports show **sanitized untrusted HTML plus restrictive URL policy plus a browser-reachable off-policy destination**. For BiDi cases, emphasize visual deception and content-integrity impact rather than generic XSS unless script execution is separately proven.

### 2. CrowdSec AppSec body-inspection bypass framing

Where to look:

- Targets that advertise or disclose CrowdSec AppSec, CrowdSec bouncers, Coraza/CRS-style body rules, or `crowdsec` versions `>= 1.5.0, <= 1.7.7`.
- Apps where previous payloads were blocked only when submitted as ordinary `Content-Length` requests.
- JSON, XML, form, or upload endpoints where the suspected rule zone is `REQUEST_BODY`, `BODY_ARGS`, `ARGS_POST`, `JSON`, or `XML`.

Safe validation path:

1. Establish a benign baseline request that triggers a known body-inspection rule or program-approved test rule with normal `Content-Length` framing.
2. Replay the same benign marker using chunked HTTP/1.1 or HTTP/2 DATA-frame body framing without `content-length`.
3. Compare the app response, CrowdSec/AppSec logs available to the program, and whether the marker is forwarded while body rules stay silent.
4. Keep the payload non-exploitative: use a harmless WAF test marker or a program-provided detection string instead of a real injection payload.

Reporting heuristic: the key proof is **same body content blocked under normal framing but allowed under chunked or HTTP/2 no-length framing**. Include the request framing difference, affected rule zone, and absence of WAF log signal if the program can confirm it.

### 3. Deno TLS retry plaintext boundary

Where to look:

- Deno `>= 2.0.0, < 2.7.8` services or CLIs using Node-compatible `node:tls` or `node:https` with `autoSelectFamily` enabled.
- Clients that write request bodies, greetings, tokens, or protocol data before the `secureConnect` event.
- Dual-stack environments where an on-path tester can safely fail the first address-family attempt in a lab or staging network.

Safe validation path:

1. Prefer local reproduction with the advisory's two-process pattern: one listener to observe whether bytes are TLS ClientHello data or plaintext, and one Deno TLS client configured with a failing first address and a controlled second address.
2. Use fake tokens and fixed canary strings only.
3. If assessing a real product, first prove vulnerable code patterns by source review or dependency/version evidence; escalate to network-path testing only when explicitly authorized.
4. Capture whether writes happen before `secureConnect`; if the application waits for `secureConnect`, the practical exploit path is weaker even on a vulnerable runtime.

Reporting heuristic: frame this as **transport-state confusion after retry**. High-signal evidence includes Deno version, `autoSelectFamily` behavior, pre-`secureConnect` writes, and a lab capture showing canary plaintext where TLS bytes were expected.

### 4. Langroid SQLChatAgent prompt-to-SQL execution boundary

Where to look:

- Python projects using `langroid < 0.63.0`, especially demos, internal tools, data assistants, analytics bots, or support agents that expose `SQLChatAgent` to untrusted or semi-trusted prompts.
- Database roles with execution/file primitives such as PostgreSQL `pg_execute_server_program` / `COPY ... FROM PROGRAM`, MySQL `FILE`, SQL Server `xp_cmdshell`, extension creation, unsafe UDFs, or broad DDL rights.
- RAG or agent flows where external data returned to the LLM can become indirect prompt injection.

Safe validation path:

1. Confirm the Langroid version and whether `SQLChatAgent` is enabled for user-controllable questions or retrieved content.
2. Start with a read-only canary: ask for a harmless constant or a table-limited `SELECT` and verify the generated SQL path.
3. In a local lab using a deliberately over-privileged disposable database role, reproduce the advisory's dangerous-SQL path with a benign command marker such as `id` or a fixed temp-file write.
4. For production or bug-bounty targets, do not execute database host commands. Instead, show that the agent accepts attacker-shaped instructions that produce non-`SELECT` or dangerous SQL and that the configured role would make those operations impactful.
5. Check the fixed behavior: version `0.63.0` defaults to a SELECT-only parsed allowlist, with `allow_dangerous_operations=True` as a conscious opt-out.

Reporting heuristic: the strongest report ties together **untrusted prompt influence, unrestricted SQL execution, and a database role capable of host/file impact**. If the DB role is read-only, report it as an agent-tool policy bypass or data-integrity risk rather than RCE.

## Non-signal this hour

Reviewed but not promoted as new standalone Skillz guidance:

- `GHSA-273h-gvwr-c3qj` / `CVE-2026-44981` CrowdSec LAPI gzip decompression DoS. Useful for resilience testing, but it is availability-only and LAPI is loopback-only by default, so it was not promoted beyond noting adjacent CrowdSec exposure.
- CISA KEV remained catalog `2026.05.27` with `CVE-2026-48027` Nx Console embedded malicious code, `CVE-2026-45321` TanStack unspecified vulnerability, and `CVE-2026-8398` Daemon Tools Lite embedded malicious code; no new operator workflow was added beyond existing supply-chain coverage.
- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits `/feed/` returned 403 in this pass but prior state stayed on the already-covered zizmor GitHub Actions static-analysis article.
- ProjectDiscovery RSS stayed unavailable/404 and prior blog material remained already-covered Neo / Nuclei / DAST proof-loop guidance.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [Symfony URL allowlist parser differential advisory (`GHSA-qc95-4862-92fh`)](https://github.com/advisories/GHSA-qc95-4862-92fh)
- [Symfony BiDi URL spoofing advisory (`GHSA-h5vq-qfcg-4m6p`)](https://github.com/advisories/GHSA-h5vq-qfcg-4m6p)
- [CrowdSec AppSec chunked / HTTP/2 body bypass advisory (`GHSA-rw47-hm26-6wr7`)](https://github.com/advisories/GHSA-rw47-hm26-6wr7)
- [Deno TLS retry plaintext advisory (`GHSA-chqv-56wv-7564`)](https://github.com/advisories/GHSA-chqv-56wv-7564)
- [Langroid SQLChatAgent prompt-to-SQL RCE advisory (`GHSA-mxfr-6hcw-j9rq`)](https://github.com/advisories/GHSA-mxfr-6hcw-j9rq)
