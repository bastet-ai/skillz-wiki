# AI, MCP, deserialization, command, and path-boundary batch

**Sources:** GHSA-6m5f-673f-5vh7 / CVE-2026-7669, GHSA-xqxw-r767-67m7 / CVE-2026-7597, GHSA-gc8w-x73w-p4rh / CVE-2026-7600, GHSA-gc2j-wpjv-jhrw / CVE-2026-7645

## Why this matters

This batch groups four agent/AI-adjacent package issues that all collapse a data boundary into code or filesystem authority:

- SGLang `get_tokenizer` / HuggingFace transformer handling can reach unsafe deserialization paths in `sglang <= 0.5.9`.
- `mem0ai < 2.0.0b2` uses Python pickle load/dump behavior in FAISS vector-store handling.
- `yii2-mcp-server <= 1.0.2` exposes MCP command helpers that can be driven to OS command injection.
- `sublinear-time-solver <= 1.5.0` exposes an MCP `export_state` path traversal primitive.

Several advisories have public exploit references and no fixed version listed. Treat exposed MCP/agent endpoints as control-plane surfaces, not convenience APIs.

## Operator triage

1. Inventory deployments of `sglang`, `mem0ai`, `yii2-mcp-server`, and `sublinear-time-solver`, especially internet-facing labs, demos, and internal agent workbenches.
2. Upgrade `mem0ai` to 2.0.0b2+; for packages without patched versions, remove exposure, pin behind authenticated administrative access, or disable the vulnerable functions.
3. For SGLang, disable untrusted tokenizer/model references and run model loading in a sandbox with no secrets or write access until a fixed version is available.
4. Replace pickle-based vector-store import/export with signed, schema-validated formats where possible; otherwise only load artifacts from a trusted provenance chain.
5. Disable MCP command execution and state-export tools unless each argument is allowlisted, canonicalized, and executed without a shell.

## Hunt prompts

- SGLang requests that reference unexpected HuggingFace repositories, local paths, or tokenizer artifacts.
- FAISS/vector-store loads from user-writable directories, uploaded archives, or remote URLs.
- MCP tool calls named like `yii_execute_command`, `yii_command_help`, `export_state`, or similar with shell metacharacters or path traversal tokens.
- New files written outside intended export directories after MCP state-export calls.

## Durable controls

- Model/tokenizer loading is code loading until proven otherwise; isolate it from application secrets and production networks.
- Do not deserialize pickle or model artifacts from untrusted users in the main service process.
- MCP tools should be capability-scoped per caller, with typed arguments and no generic command execution surface by default.
- Canonicalize filesystem paths against an allowlisted root after decoding and symlink resolution, then enforce a final open/create-at-root primitive.
- Add egress controls for agent runtimes so a deserialization bug cannot immediately become credential theft.
