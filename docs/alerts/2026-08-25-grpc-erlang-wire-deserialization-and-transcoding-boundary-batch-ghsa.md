---
title: gRPC-Erlang wire-deserialization, transcoding, and body-boundary batch
---

# gRPC-Erlang wire-deserialization, transcoding, and body-boundary batch

Source: GitHub Security Advisories, published 2026-08-25. This wave targets the Elixir `grpc` Hex package (and the Erlang/BEAM runtime it runs on) and is durable because it exposes a reusable **protocol-trust boundary** that operators hit whenever an Erlang/Elixir service speaks gRPC: what the wire deserializer will materialize, how the HTTP-to-gRPC transcoding layer binds request identity, and where the body/encoding size limits actually start.

- [GHSA-grp7-v8xh-rj7h](https://github.com/advisories/GHSA-grp7-v8xh-rj7h) / CVE-2026-48853, **Critical.** `GRPC.Codec.Erlpack.decode/2` calls `:erlang.binary_to_term/1` on the raw gRPC message body without `:safe`. An unauthenticated peer reaching a `Content-Type: application/grpc+erlpack` endpoint can crash the whole BEAM node (atom-table exhaustion) or, if a decoded `fun` term reaches a call site that applies it, achieve RCE in the server process.
- [GHSA-mwr4-5g34-j5cq](https://github.com/advisories/GHSA-mwr4-5g34-j5cq) / CVE-2026-48599, **High.** The HTTP-to-gRPC transcoding layer's `GRPC.Server.Transcode.map_request/5` uses `Map.merge/2` with path bindings at *lowest* precedence, so query-string and request-body parameters silently overwrite path-bound fields. An attacker who reaches a transcoded endpoint like `GET /users/{user_id}/profile` sends `?user_id=victim` and substitutes any path-bound identifier, bypassing authorization, multi-tenancy, and ownership checks that key off the path-derived value.
- [GHSA-q8gf-9rvj-gmgj](https://github.com/advisories/GHSA-q8gf-9rvj-gmgj) / CVE-2026-48854, **High.** `read_full_body/3` accumulates every chunk into one growing binary with no size cap; when the client omits `grpc-timeout` the read timeout resolves to `:infinity`, so a single unauthenticated connection can hold a connection open indefinitely while memory grows to OOM.
- [GHSA-6ccx-9c9f-327w](https://github.com/advisories/GHSA-6ccx-9c9f-327w) / CVE-2026-53430, **High.** `GRPC.Compressor.Gzip.decompress/1` calls `:zlib.gunzip/1` directly on attacker-controlled bytes with no size limit, ratio check, or incremental decode. A small gzip frame with `grpc-encoding: gzip` decompresses to gigabytes and OOM-kills the node in a single request. `max_receive_message_length` only bounds the *decompressed* message, so it does not protect here.

## Why this is a reusable operator boundary

The common shape: **a network protocol surface where the trust decision and the sink operate on different guarantees.**

- The erlpack codec trusts that wire bytes are safe to `binary_to_term`, the sink (`erlang:apply` / `Enum.map` / a fun call) does not.
- The transcoder trusts that path bindings are authoritative, but the merge order makes the attacker's body/query authoritative.
- The body reader trusts the stream will end, but `:infinity` timeout plus unbounded accumulation removes that guarantee.
- The gzip compressor trusts `max_receive_message_length` to bound memory, but the limit is applied *after* full decompression.

If you operate against any Erlang/Elixir gRPC service, a backend RPC, a transcoded REST-over-gRPC facade, a control plane, a telemetry sink, these are the four places to probe.

## Preconditions

- Explicit permission to test the target service or an authorized lab copy.
- The service speaks gRPC (or a REST-over-gRPC transcode endpoint) and is reachable.
- You can craft raw gRPC frames or use a gRPC client to control `Content-Type`, `grpc-encoding`, `grpc-timeout`, body, and query parameters.

## Replayable validation boundaries

### 1. Unsafe wire deserialization (atom exhaustion / fun materialization)

- Confirm the codec. Send a minimal gRPC unary call with `Content-Type: application/grpc+erlpack` and a payload that is a valid `erl`-encoded term.
- **DoS path:** encode a term with a large count of *fresh* atoms and observe whether the node's atom table approaches its bound. Proof is the node crashing or `erlang:atom_list()`/`:erlang.system_info(:atom_count)` climbing, keep the payload to a synthetic atom storm, never a real credential or secret string.
- **RCE path:** only claim it if a decoded `fun`/external-fun term demonstrably reaches a call site that applies it. Prove with a canary term that, when applied, writes a marker file or echoes an inert value, never a destructive command. If the sink is not proven, report the deserialization primitive and label the RCE as inference.

### 2. Transcoding path-binding override (authz bypass)

- Deploy/point at a transcoded route whose handler authorizes on the path-bound field (e.g. `request.user_id` from `/users/{user_id}/profile`).
- Send the same route with `?user_id=<victim>` (and a body variant for POST/PUT) and record whether the handler's authorization decision flips to the attacker-supplied value.
- Prove with two synthetic identities: your own authorized `user_id` and a second canary `user_id`. Positive result = the response is the canary's resource, not a 403. Never target real user data or production records.

### 3. Unbounded body accumulation

- Open a unary RPC, omit `grpc-timeout`, and trickle the body (a few bytes per second) while watching process memory.
- Stop at the first sustained memory climb; the proof is the growth trend plus the missing size cap, not a full OOM on a shared node. Do not exhaust a production or shared BEAM node.

### 4. Gzip decompression bomb

- Send a single gRPC frame with `grpc-encoding: gzip` carrying a small highly-compressible payload (e.g. a few KB of zeros, ~1000:1) and record the decompressed size the server attempts to allocate.
- Proof is the decompression ratio and the server memory spike/OOM on a lab node, keep the payload tiny and target a disposable instance only.

## Reporting heuristics

- Report each boundary separately with the exact sink symbol (`binary_to_term/1`, `map_request/5` merge order, `read_full_body/3`, `:zlib.gunzip/1`) and the missing guard (`:safe`, merge precedence, body cap, decompression ratio limit).
- For the transcoding issue, always show both the authorized path value and the attacker-substituted value, and the resulting resource identity.
- Keep DoS proofs to memory-trend / ratio evidence on lab or authorized nodes; do not bring down shared or production BEAM nodes.
- Record the exact `grpc` package version and whether `max_receive_message_length` / `grpc-timeout` defaults were in play.

## Notes on skipped / related items from this scan

- The adjacent DoS-only and auth-bypass advisories in the same 2026-08-25 GitHub wave (PraisonAI/mcp-shell, Chainlit MCP, Echo `%2F`, urllib cross-origin redirect headers) were folded into their own follow-ups rather than this Erlang page, see the PraisonAI/mcp-shell/Chainlit agent-runtime follow-up and the canonicalization-differentials page.
- gRPC-Erlang is treated as its own protocol boundary rather than a generic "deserialization" note because the transcoding path-binding override and the body/encoding size-limit gaps are distinct, replayable patterns that recur in any REST-over-gRPC Erlang service.
