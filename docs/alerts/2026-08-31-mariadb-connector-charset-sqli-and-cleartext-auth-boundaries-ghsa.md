---
title: MariaDB connector multi-byte charset SQL injection and cleartext auth-plugin boundary checks
---

# MariaDB connector multi-byte charset SQL injection and cleartext auth-plugin boundary checks

An August 28 GitHub-reviewed wave across the MariaDB connector family yields two durable operator patterns: (1) **client-side Buffer parameter escaping under a multi-byte client charset whose trail-byte range includes `0x5C`**, which lets an attacker-controlled lead byte swallow the connector's escape backslash and break out of the string literal, and (2) **cleartext-password authentication plugins (`mysql_clear_password`, `dialog`/PAM) that are not gated on a secure transport**, so a hostile or man-in-the-middle server can receive the account password in plaintext over plain TCP. A third pattern, **mid-session `character_set_client` divergence between driver and server**, is the charset-confusion primitive that re-enables byte-wise quoting defeats.

Sources:

- [GHSA-g5xc-5w98-jfvm: mariadb-connector-nodejs multi-byte-charset Buffer-parameter SQL injection](https://github.com/advisories/GHSA-g5xc-5w98-jfvm), fix `0148cadd` ([CONJS-350](https://jira.mariadb.org/browse/CONJS-350))
- [GHSA-xvr9-35cr-46v9: mariadb-java-client mid-session charset divergence](https://github.com/advisories/GHSA-xvr9-35cr-46v9)
- [GHSA-5rqc-86vf-g8r2: mariadb-connector-r2dbc mid-session charset divergence](https://github.com/advisories/GHSA-5rqc-86vf-g8r2), fix `38bad9af` ([R2DBC-124](https://jira.mariadb.org/browse/R2DBC-124))
- [GHSA-cqhc-2h57-wpxf: mariadb-connector-nodejs cleartext password leak to a MITM despite `ssl: true`](https://github.com/advisories/GHSA-cqhc-2h57-wpxf)
- [GHSA-g9jj-cgmh-9f38: mariadb-java-client cleartext password disclosure on the initial handshake](https://github.com/advisories/GHSA-g9jj-cgmh-9f38)
- [GHSA-42r5-vhpq-m858: mariadb-connector-nodejs PAM/dialog cleartext transmission](https://github.com/advisories/GHSA-42r5-vhpq-m858)
- [GHSA-qxvw-fvwx-5cp7: mariadb-java-client PAM/dialog cleartext transmission](https://github.com/advisories/GHSA-qxvw-fvwx-5cp7)
- [GHSA-c857-9x2m-cvh2: mariadb-connector-r2dbc cleartext password disclosure to a MITM server](https://github.com/advisories/GHSA-c857-9x2m-cvh2)

Reviewed package ranges: node connector `<3.2.4`, `>=3.3.0,<3.3.3`, `>=3.4.0,<3.4.6`, `>=3.5.0,<3.5.3`; Java connector `<2.7.14`, `>=3.0.0,<3.3.5`, `>=3.4.0,<3.4.3`, `>=3.5.0,<3.5.9`; R2DBC `<1.4.1`. Confirm exact package, connector version, client charset, TLS configuration, and fixed-build behavior before reporting.

!!! warning "Authorized validation only"
    Use a disposable MariaDB/MySQL server and a lab network namespace or container with no route to production, cloud metadata, or internal services. Generate a test CA and fake certificates; use synthetic accounts and a marker-only SQL sink. Never capture real credentials, target a third-party database, relay production traffic, or escalate against a production account.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-g5xc-5w98-jfvm](https://github.com/advisories/GHSA-g5xc-5w98-jfvm) | mariadb-connector-nodejs | client-side Buffer escaping under `big5`/`gbk`/`sjis`/`cp932`/`gb18030` swallows the `0x5C` escape byte, breaking out of the string literal | Add non-UTF-8 client charsets to any review that binds untrusted data into a `Buffer` query parameter; binary/server-side prepared statements are not affected. |
| [GHSA-xvr9-35cr-46v9](https://github.com/advisories/GHSA-xvr9-35cr-46v9) / [GHSA-5rqc-86vf-g8r2](https://github.com/advisories/GHSA-5rqc-86vf-g8r2) | mariadb-java-client / r2dbc-mariadb | a hostile server or stored routine/trigger switches `character_set_client` mid-session; the driver keeps UTF-8 while the server reinterprets bytes | Treat any path that can steer `SET NAMES`/session charset state to a non-UTF-8 value as a charset-confusion primitive that can re-enable quoting/escaping defeats. |
| [GHSA-cqhc-2h57-wpxf](https://github.com/advisories/GHSA-cqhc-2h57-wpxf) | mariadb-connector-nodejs | fingerprint/identity validation runs *after* the auth exchange, so a MITM presenting any certificate receives the password before the connection is aborted | For `ssl: true` + no pinned CA, the credential is transmitted before identity check; capture only a synthetic credential on an owned MITM listener. |
| [GHSA-g9jj-cgmh-9f38](https://github.com/advisories/GHSA-g9jj-cgmh-9f38) | mariadb-java-client | `sslMode=verify-full`/`verify-ca` accepts an untrusted cert at the TLS layer and binds fingerprint into the auth exchange, but the initial-handshake path is not covered | `mysql_clear_password` named in the initial handshake leaks the password in cleartext before the fingerprint check; prove with a fake account against an owned listener. |
| [GHSA-42r5-vhpq-m858](https://github.com/advisories/GHSA-42r5-vhpq-m858) / [GHSA-qxvw-fvwx-5cp7](https://github.com/advisories/GHSA-qxvw-fvwx-5cp7) | node + Java connectors | PAM/`dialog` plugin handler did not inherit the `mysql_clear_password` secure-transport gate, so it sends the password in cleartext over plain TCP | A hostile/MITM server can issue an `Authentication Switch Request` for `dialog` and read the plaintext password; the `AuthenticationPlugin` capability is missing. |
| [GHSA-c857-9x2m-cvh2](https://github.com/advisories/GHSA-c857-9x2m-cvh2) | r2dbc-mariadb | clear-text password plugins are not gated on transport encryption at the interface level | Same as above: `mysql_clear_password`/`dialog` over plain TCP exposes the password. |

## Multi-byte-charset Buffer-escape SQL injection (the durable primitive)

This is the classic multi-byte escaping bypass, now in the connector's client-side Buffer path:

- Under `utf8mb4` (the default) or any charset whose trail-byte range does **not** include `0x5C`, byte-wise backslash escaping is sound.
- Under `big5`, `gbk`, `sjis`, `cp932`, or `gb18030`, the SQL lexer performs multi-byte recognition (`my_ismbchar`) **before** interpreting escape sequences. An attacker byte the lexer treats as a valid lead byte, followed by `0x5C`, is consumed as a single multi-byte character. The connector's inserted escape backslash is swallowed as that character's trail byte, so the following `0x27` is no longer escaped and closes the string literal.
- Only `Buffer` (binary) parameters that are escaped into the SQL text are affected. Parameters bound through the binary/server-side prepared-statement path are sent out-of-band and are not affected.

### Bounded PoC workflow

1. Provision a disposable MariaDB server and a client that uses the affected node connector version with `character_set_client` set to one of the five charsets. Use a synthetic low-privilege account.
2. Baseline a parameterized query that binds an inert `Buffer` containing only safe text; record the prepared SQL text the connector emits.
3. Craft the smallest `Buffer` value: a valid lead byte for the chosen charset, then `0x5C` (backslash), then `0x27` (quote), then a marker that would terminate the literal and append an inert `UNION SELECT` that returns only a synthetic constant. Do **not** read real tables or escalate.
4. Capture the connector's escaped SQL text and the server's parse result. A positive result is the marker constant returned as a new column, proving the literal terminated early.
5. Add controls: the same payload under `utf8mb4` (must stay inert), a binary prepared-statement path (must stay inert), and the fixed connector version (must reject or contain).
6. Repeat on the Java connector only if it shares the same client-side escaping path for `Buffer`-equivalent binary parameters under the same charsets; otherwise note it as out of scope.

Strong evidence is **non-UTF-8 client charset + untrusted `Buffer` bytes -> connector escapes byte-wise -> server lexer consumes the escape backslash as a trail byte -> the closing quote is unescaped -> inert marker SELECT executes**. Do not read production data, do not escalate the database account, and do not target any real server.

## Cleartext auth-plugin transport gating

The `mysql_clear_password` plugin is gated behind a secure connection: the driver refuses to transmit the password in cleartext over plain TCP. The sibling PAM/`dialog` plugin handler did **not** override that gate and inherited the default, so it was not subject to the same secure-transport requirement. Additionally, on the fingerprint-validation paths (`ssl: true` with no pinned CA, and `sslMode=verify-full`/`verify-ca` on the initial handshake), the credential is transmitted *before* the identity/fingerprint check runs, so an on-path attacker presenting any certificate captures the password before the connection is torn down.

### Bounded PoC workflow

1. Run an owned plain-TCP MariaDB listener (a fake server that speaks enough of the protocol to issue an `Authentication Switch Request` naming `mysql_clear_password` or `dialog`). Use a lab network namespace with no production routes.
2. Configure the affected connector to connect to that listener with `sslMode=DISABLE` (or `ssl: false`) and a synthetic low-privilege account with a marker password.
3. Capture the wire bytes. A positive result is the marker password appearing in cleartext in the `dialog`/`mysql_clear_password` auth packet.
4. For the MITM variant: insert an owned TLS-terminating proxy that presents a self-signed certificate, capture the cleartext password during the handshake, and confirm the connector then aborts the connection on fingerprint mismatch. Record only that the synthetic credential was observed; do not relay to a real server.
5. Add controls: a secure-transport connection (must not leak), a `dialog` plugin under TLS, and the fixed connector version (must gate the clear-text plugin on a secure transport).

Strong evidence is **plain-TCP connection + hostile/MITM server naming `dialog`/`mysql_clear_password` -> connector sends the synthetic password in cleartext -> fixed version requires TLS before the clear-text plugin**. Do not use real credentials, do not relay production traffic, and do not capture internal hostnames.

## Charset-confusion as a quoting-defeat primitive

The mid-session `character_set_client` divergence advisories (Java + R2DBC) are the same trust-confusion shape as the Buffer-escape SQLi: the driver and the server interpret the same bytes under different encodings after the server switches the client charset. This is the primitive that can defeat byte-wise quoting/escaping when client and server disagree on a multi-byte encoding. The R2DBC fix rejects any post-init charset change to a non-UTF-8 value with `R2dbcNonTransientResourceException` (SQLState `08000`).

Reusable heuristic: in any review of a database connector, enumerate the paths that can steer `SET NAMES` / session-state charset tracking to a non-UTF-8 value (stored routine, trigger, server configuration, hostile server) and confirm whether the driver re-validates the encoding assumption after the switch.

## Operator triage

1. **Start with the client charset.** Multi-byte escaping defeats only fire when the connection charset is `big5`, `gbk`, `sjis`, `cp932`, or `gb18030`. Audit the connector configuration and any `SET NAMES` / `SET character_set_client` in the target's startup path.
2. **Separate text-bound parameters from binary prepared statements.** Only parameters escaped into the SQL text are affected; binary/server-side prepared statements are out of scope.
3. **Bind the auth transport to the plugin.** For any review of a DB connector, confirm that every clear-text password plugin is gated on a secure transport and that identity/fingerprint validation happens *before* the credential is transmitted.
4. **Keep all proofs disposable.** Use a lab server, a synthetic account, a marker-only SQL sink, an owned MITM listener, and generated test certificates. Do not read production data, escalate a database account, or capture real credentials.

## Reporting notes

- Lead with the precise trust boundary: **non-UTF-8 client charset + untrusted `Buffer` -> escaped SQL text -> literal breakout**, **clear-text auth plugin over plain TCP / before identity validation**, or **mid-session charset divergence defeating byte-wise quoting**.
- Include connector version, client charset, TLS configuration, the raw and canonical SQL text (for the SQLi) or the wire bytes (for the credential leak), and a patched negative control.
- Keep all proof artifacts disposable: synthetic accounts, marker constants, owned listeners, generated certificates. Do not include real passwords, production table data, internal hostnames, or metadata in wiki/report evidence.
