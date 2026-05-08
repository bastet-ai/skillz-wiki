# Parser, deserialization, and crypto-boundary batch

**Signal:** The **2026-05-08 23:15 UTC** scan added parser/deserialization and crypto-policy advisories across LangChain, eml_parser, phpseclib, and Paramiko.

## Advisory cluster

- **LangChain broad object revival** — [GHSA-pjwx-r37v-7724](https://github.com/advisories/GHSA-pjwx-r37v-7724): runtime paths in `langchain-core` used overly broad `load()` allowlists, allowing attacker-controlled serialized constructor dictionaries to revive trusted LangChain-serializable objects beyond what those paths needed. Patch to **0.3.85+** or **1.3.3+**.
- **eml_parser recursive message bodies** — [GHSA-g47v-rwmh-r9f8](https://github.com/advisories/GHSA-g47v-rwmh-r9f8): nested `message/rfc822` attachments could recurse until `RecursionError` and crash a parser worker. Patch to **3.0.1+**.
- **phpseclib ASN.1 binaryfield integer amplification** — [GHSA-2f25-pfq3-c7h8](https://github.com/advisories/GHSA-2f25-pfq3-c7h8): untrusted ASN.1 inputs such as certificates and keys needed guardrails around large binaryfield integers. Patch `phpseclib/phpseclib` to **3.0.34+**.
- **Paramiko RSA SHA-1 acceptance** — [GHSA-r374-rxx8-8654](https://github.com/advisories/GHSA-r374-rxx8-8654): `paramiko <=4.0.0` accepted SHA-1 in `rsakey.py`; treat SHA-1 acceptance as crypto-policy drift even when the advisory is low severity.

## Why this matters

Parsers and deserializers fail safely only when they have narrow type budgets, depth budgets, and algorithm policies. “Trusted object” allowlists, email MIME recursion, ASN.1 length fields, and legacy signature algorithms are all attacker-controlled interpretation surfaces when they touch uploaded files, model/agent state, certificates, or SSH keys.

## Triage

1. Patch `langchain-core`, `eml_parser`, `phpseclib/phpseclib`, and Paramiko where these packages process untrusted state, files, mail, certs, keys, or agent payloads.
2. Inventory any endpoint or worker that accepts serialized LangChain payloads, EML uploads, X.509/PKCS inputs, or user-supplied SSH key material.
3. Put recursion depth, object count, byte count, and wall-clock limits around mail and ASN.1 parsing workers.
4. Replace broad deserialization allowlists with path-specific object allowlists; reject constructor dictionaries for classes the endpoint does not explicitly need.
5. Disable SHA-1 signature acceptance in policy where possible and alert on negotiation/use of SHA-1 in SSH/RSA verification paths.

## Durable controls

- Make parser budgets explicit and test them with nested, oversized, and malformed fixtures.
- Separate “load trusted project state” from “parse user-controlled payload” APIs; they should not share the same allowlist.
- Run complex parsers in crash-isolated workers with bounded memory and restart throttling.
- Treat crypto algorithm acceptance as configuration drift and enforce centrally audited allowlists.
