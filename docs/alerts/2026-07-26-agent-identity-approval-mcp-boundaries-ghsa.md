---
title: Agent identity, compression, approval, MCP, and registration boundaries
---

# Agent identity, compression, approval, MCP, and registration boundaries

A July 26 advisory wave and a July 28 Hermes update yield five reusable operator checks: mutable chat profile data treated as an allowlist identity, task state reintroduced as a high-authority prompt after context compression, unauthenticated loopback callbacks supplying approval identity, approval cards that omit execution-relevant fields, and low-privilege or anonymous routes reaching privileged MCP and device-registration actions.

Sources:

- [GHSA-6r3x-gc73-h69w / CVE-2026-17432: Hermes SimpleX authorization record](https://github.com/advisories/GHSA-6r3x-gc73-h69w)
- [Primary Hermes issue #44729](https://github.com/NousResearch/hermes-agent/issues/44729)
- [Hermes commit that introduced display-name matching](https://github.com/NousResearch/hermes-agent/commit/490c486ff65b766d9de0fe0e6f26e1778aaa8fb3)
- [GHSA-xq8w-9jvx-gm3v / CVE-2026-10221: Hermes todo snapshot prompt injection](https://github.com/advisories/GHSA-xq8w-9jvx-gm3v)
- [Primary Hermes compression issue #26979](https://github.com/NousResearch/hermes-agent/issues/26979)
- [Hermes todo snapshot fix PR #69860](https://github.com/NousResearch/hermes-agent/pull/69860)
- [GHSA-6frr-4xvp-cwch / CVE-2026-17433: NanoClaw loopback approval callback](https://github.com/advisories/GHSA-6frr-4xvp-cwch)
- [Primary NanoClaw issue #2761](https://github.com/nanocoai/nanoclaw/issues/2761)
- [GHSA-m5r3-634q-m3rj / CVE-2026-17434: NanoClaw MCP approval representation mismatch](https://github.com/advisories/GHSA-m5r3-634q-m3rj)
- [Primary NanoClaw issue #2762](https://github.com/nanocoai/nanoclaw/issues/2762)
- [NanoClaw fix PR #2998](https://github.com/nanocoai/nanoclaw/pull/2998)
- [GHSA-hp8g-g2qj-wgpj / CVE-2026-66012: SiYuan anonymous Publish-to-MCP chain](https://github.com/advisories/GHSA-hp8g-g2qj-wgpj)
- [Primary SiYuan advisory GHSA-cvhv-7xhj-xjp8](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-cvhv-7xhj-xjp8)
- [SiYuan authorization fix](https://github.com/siyuan-note/siyuan/commit/c72ca4cd09019e5f64afdee8f8c6ec5ef34858db)
- [GHSA-jg8p-j9v5-g5x5 / CVE-2026-66013: OpenRemote console registration](https://github.com/advisories/GHSA-jg8p-j9v5-g5x5)
- [Primary OpenRemote advisory GHSA-gpfc-h59v-63cv](https://github.com/openremote/openremote/security/advisories/GHSA-gpfc-h59v-63cv)

The GitHub records in this wave are unreviewed. There are material Hermes version discrepancies. The SimpleX record labels release `2026.6.5` affected and describes commit `490c486...` as a patch, while the primary issues state that `v2026.6.5` is unaffected and that this commit **introduced** display-name matching on unreleased `main`. The compression record's prose says versions through 0.12.0, its package range says through 0.19.0, and it lists no patched release; PR #69860 merged on July 23, after the latest listed `v2026.7.20` release. Treat exact source revision and observed behavior—not either sparse range—as authoritative evidence.

!!! warning "Authorized validation only"
    Use synthetic contacts, disposable agent groups, inert todo markers, instrumented no-tool model stubs, inert pending approvals, fake MCP server values, temporary SiYuan workspaces, fake device tokens, and two-user labs. Never plant instructions in a production agent, trigger terminal/filesystem/browser/network tools, approve a live shell/write/spend action, read real notes or credentials, install a plugin, overwrite a real notification token, or use another tenant's asset identifier.

## Build an identity-and-authority map

For every messaging or agent control surface, record these values separately:

| Boundary | Untrusted representation | Authority-bearing representation | Safe proof |
| --- | --- | --- | --- |
| Chat ingress | display name, handle, nickname | stable platform contact ID | allow/deny decision table |
| Context compression | task text copied from tool state | real user turn versus synthetic scaffolding | marker-only pre/post-compression transcript diff |
| Loopback callback | JSON `user.id` | authenticated gateway or OS peer | inert pending approval remains/clears |
| Human approval | rendered card | complete stored payload and digest | visible-vs-applied field diff |
| MCP route | anonymous/reader session | tool-specific role and capability | harmless tool inventory or marker note |
| Device registration | request-supplied asset ID | asset owner/session binding | fake token update in two-user lab |

Do not collapse these into one generic “missing authorization” or “prompt injection” claim. The useful finding identifies where attacker-controlled data is first mistaken for authenticated identity, fresh user intent, or privileged authority.

## Hermes SimpleX: stable contact ID versus mutable display name

The primary Hermes issues trace a SimpleX `newChatItem` through the adapter into `SessionSource`. The adapter preserves the stable `contactId` as `user_id` but also copies mutable display-name data into `user_name`. An unreleased `main` change then adds `user_name` to the set that can satisfy `SIMPLEX_ALLOWED_USERS`.

### Reachability prerequisites

Confirm:

- the tested source revision contains the SimpleX display-name matching branch;
- the SimpleX gateway is enabled and reachable by the test contacts;
- `SIMPLEX_ALLOWED_USERS` contains a display name rather than only a stable contact ID;
- the second owned contact can choose the same display name;
- authorization gates an agent or tool path that matters to the engagement.

### Two-contact decision table

1. Create two disposable SimpleX contacts with distinct stable IDs.
2. Give both contacts the same harmless display-name canary.
3. Configure the lab gateway first with contact A's stable ID only.
4. Submit the same inert text message from both contacts and capture `user_id`, `user_name`, allowlist values, and the final authorization result.
5. Replace the allowlist with only the colliding display name and repeat.
6. Add controls for a non-colliding display name and the exact stable ID of contact B.

A positive result is **different authenticated contact ID + matching mutable display name -> authorization succeeds**. Stop at an inert message acknowledgement; do not invoke terminal, filesystem, browser, or external-service tools.

Report the tested commit range explicitly. Do not claim released `v2026.6.5` is vulnerable unless that tag independently reproduces the branch.

## Hermes compression: task state must not become fresh user intent

The compression issue traces a second Hermes boundary. Active todo content is rendered by `TodoStore.format_for_injection()` and preserved across context compaction. The affected shape appended that text as a standalone `{role: "user"}` row at the transcript tail. A task copied from user or retrieved content could therefore return after compaction looking like a fresh user turn rather than quoted tool state.

The merged PR changes this behavior, but it does **not** simply delete todo preservation or sanitize natural-language instructions. It merges the snapshot into a trailing real user turn when one exists, flags the standalone fallback as synthetic for scaffolding-only histories, refreshes stale snapshots instead of stacking them, and skips empty/all-completed stores. The longer-term design noted in the PR is typed tool state rather than a user-role row.

### Marker-only compression harness

Test the dataflow without asking a live model to execute anything:

1. Check out the exact affected revision and the merged fix (`2ca38e5df43411afe11aedfc34bfd71a2eecd4bb`) in separate disposable environments.
2. Replace the model/tool execution boundary with a recorder that stores ordered message roles, content hashes, synthetic flags, and whether a row is classified as a real user turn. It must never dispatch a tool.
3. Seed one pending todo with an inert instruction-shaped marker such as `CANARY_TASK_TEXT_DO_NOT_EXECUTE`; keep a benign real user turn in the transcript.
4. Force `_compress_context()` with a deterministic compressor stub. Compare the transcript immediately before and after compaction.
5. Repeat with: no real user turn, a continuation-marker tail, a summary-as-user tail, a multimodal real-user tail, one stale prior snapshot, and an all-completed todo store.
6. Run a negative control with a normal pending task and verify task continuity still works. Do not use shell commands, secret-shaped strings, URLs, or external callbacks as markers.

Evidence matrix:

| Fixture | Affected evidence | Fixed evidence |
| --- | --- | --- |
| real user tail + active todo | separate final user row contains marker | marker is attached to the existing real user row; no extra user/user turn |
| scaffolding-only tail | marker-bearing row can appear as an unqualified user turn | standalone fallback carries synthetic provenance and remains classifiable as scaffolding |
| stale prior snapshot | old snapshot can survive or accumulate | old block is stripped and exactly one refreshed snapshot remains |
| all todos completed | no active state should be injected | no snapshot row or marker appears |

A bounded positive result is **attacker-influenceable task text -> compression -> new tail user-role message that loses tool-state provenance**. This proves a prompt-authority transformation and persistence primitive. It does not by itself prove safety-policy override, tool execution, data access, exfiltration, remote reachability, or cross-session persistence. Establish those preconditions separately and stop before any privileged action.

For broader agent reviews, apply the same harness to memories, plans, summaries, retrieved documents, approval explanations, and checkpoint restores. Track every state item's provenance through serialization, compaction, database projection, reload, and prompt assembly; labels held only in underscore-prefixed in-memory fields are insufficient if persistence strips them.

## NanoClaw: unauthenticated loopback approval identity

NanoClaw's gateway bridge can start a temporary webhook on `127.0.0.1`. The issue reports that the callback accepts a forwarded interaction body without a signature, bearer token, or peer binding, then passes body-supplied `interaction.user.id` to a downstream authorization check. The downstream comparison may be correct while its identity input is forged.

### Marker-only replay

1. Use a disposable NanoClaw instance with a canary agent group and one inert pending channel-registration approval.
2. Record the random loopback port and confirm the listener is reachable only from the local test context.
3. Submit a control interaction carrying an unrelated synthetic user ID; the approval must remain pending and group membership must not change.
4. Submit the same body with the expected approver's synthetic ID.
5. Capture the callback authentication state, parsed identity, authorization decision, pending-row state, and canary membership change.
6. Repeat against a fixed or instrumented build that requires a one-time secret, authenticated IPC peer, or signed gateway envelope.

The proof is **local untrusted process -> unsigned callback body -> forged approver identity -> inert pending action accepted**. Loopback binding reduces network exposure; it does not authenticate every local process or container sharing that network namespace.

## NanoClaw: bind approval display to the exact applied payload

The `add_mcp_server` issue describes a representation mismatch. The agent-controlled request contains `name`, `command`, `args`, and `env`; the vulnerable approval card showed only `name` and `command`; approval later persisted all four fields into runtime configuration.

### Approval-diff fixture

1. Instrument the MCP server apply/start boundary so it records configuration but never launches a process.
2. Submit a baseline request with a harmless command name, empty arguments, and empty environment.
3. Submit a second request with the same visible name/command plus a unique inert argument and fake environment marker.
4. Save the raw request, rendered approval card, stored approval payload, post-approval database row, materialized runtime config, and launch-recorder output.
5. Confirm whether the two requests look identical to the approver but apply different runtime configuration.
6. Repeat with the fix from PR #2998, which renders all fields, escapes invisible/fence-breaking content, bounds the card, and redacts secret-shaped values while retaining a fingerprint.

A valid result proves **execution-relevant field omitted from approval representation -> human approves incomplete view -> hidden field persists into the exact configuration later consumed**. Do not put real secrets in `env`; use a fake marker and do not start the MCP command.

Extend this test to tool approvals, workflow diffs, package installs, mounts, network destinations, cloud actions, and database queries. Compare the canonical object—not hand-built prose—to what is signed, stored, approved, and applied.

## SiYuan: anonymous Publish identity reaching workspace-wide MCP tools

The SiYuan record describes a cross-route chain: anonymous Publish mode causes a reverse proxy to attach a reader-role JWT, the kernel `/mcp` route applies only a general authentication check, and tool-level admin/read-only enforcement is absent. The dangerous outcome comes from the mismatch between the **reader identity minted by one subsystem** and the **capabilities accepted by another**.

### Bounded role/tool matrix

1. Create a temporary SiYuan workspace containing one unique canary note and no real account, sync, or plugin data.
2. Run separate fixtures for Publish disabled, Publish with authentication, and anonymous Publish.
3. For each fixture, test direct and Publish-proxied access as unauthenticated, reader, and admin identities.
4. Inventory only tool names and declared schemas first; do not invoke file-delete, rename, plugin, process, or broad workspace-read functions.
5. If authorization permits execution, invoke one harmless note/read operation scoped to the synthetic canary and one marker-only write inside the disposable workspace.
6. Capture the external route, proxy-added claims, kernel route decision, tool-level decision, and resulting marker.
7. Compare with v3.7.2 or the linked authorization fix.

The decisive evidence is **anonymous Publish request -> reader token added by proxy -> `/mcp` accepted -> a capability beyond reader intent performs a canary-only action**. Do not reproduce the published credential-read or plugin-execution chain; route, claims, tool inventory, and one disposable marker are sufficient.

## OpenRemote: create registration is not update authorization

The OpenRemote record reports that a console registration endpoint can update an existing console asset when given its identifier without authenticating or binding the request to the asset owner. This is a common device-enrollment flaw: a route intended to bootstrap a new console silently becomes an unauthenticated update primitive when an ID already exists.

### Two-user registration matrix

1. Create two synthetic tenants/users and one disposable console asset per principal.
2. Assign each asset a fake push token and unique metadata marker.
3. Replay the normal unauthenticated new-console registration with a fresh ID as a baseline.
4. Submit the same request shape with the existing ID of your second lab asset and a new fake token.
5. Query state only through the owning lab account and record whether token or metadata changed.
6. Test missing, random, same-owner, cross-owner, malformed, and duplicate IDs.
7. Repeat on 1.26.2 or the primary advisory's fixed revision.

A valid finding proves **unauthenticated registration input + known existing asset ID -> update path selected -> another synthetic owner's token/metadata changes**. Do not enumerate IDs, intercept notifications, or overwrite a production registration.

## July 29 Dynatrace MCP notebook approval follow-up

[GHSA-pc2w-4mq8-32qw](https://github.com/advisories/GHSA-pc2w-4mq8-32qw) extends the approval workflow to `@dynatrace-oss/dynatrace-mcp-server <1.8.7`. The `create_dynatrace_notebook` write tool did not call the human-elicitation gate used by five neighboring write tools. It could persist tenant-visible Markdown and DQL content without operator consent; opening DQL content may later execute it under the viewer's Dynatrace identity.

Use a fake Dynatrace HTTP backend or disposable tenant with a fake platform token. Instrument the elicitation and document-create calls, then invoke each registered write tool with marker-only arguments. Record tool annotations, scopes requested, whether elicitation occurred, the approval result, backend call count, stored content type, and returned document ID. For the notebook row, use only inert Markdown and a DQL-shaped string that the mock backend records but never evaluates. Compare pre-1.8.7 behavior with 1.8.7 and include denial/cancellation controls.

Report two edges separately: **tool call -> persistent notebook write without approval** and **stored DQL text -> later viewer-triggered evaluation**. The first can be proven with a no-op backend; do not claim the second without a disposable tenant and an instrumented no-data query. Do not expose the server publicly, use a live platform token, query logs/metrics, send messages, publish workflows, or place executable DQL in a real tenant.

## October 23 obsidian-tc follow-up: vault-selector dispatch, unenforced human declines, and enumeration-only deny lists

An October 23 four-advisory wave against `obsidian-tc` (an Obsidian vault MCP server) adds two new approval/tenancy axes and two class confirmations. All legs fixed in the 1.3.1 band; the HITL leg cites 1.31.4 — a vendor versioning discrepancy (the vault fix was developed on tag `v1.3.0`, which never published to npm), so treat published-release diffing, not tag names, as the fix boundary.

Sources:

- [GHSA-84c9-qqpq-2pq5 / CVE-2026-77366 (9.9): tokens access arbitrary configured vaults](https://github.com/advisories/GHSA-84c9-qqpq-2pq5)
- [GHSA-737x-cwfr-5vvc / CVE-2026-115477: declined HITL confirmations still execute over HTTP](https://github.com/advisories/GHSA-737x-cwfr-5vvc)
- [GHSA-cvp8-vvgf-69q4 / CVE-2026-77364: default ACL fail-open, control dirs denied only during enumeration](https://github.com/advisories/GHSA-cvp8-vvgf-69q4)
- [GHSA-c5xx-h28h-f682 / CVE-2026-77361: lexical-path ACL versus realpath containment](https://github.com/advisories/GHSA-c5xx-h28h-f682)

### Any token selects any vault through a dispatcher parameter

Tool dispatch never compared the caller-supplied `input.vault` against the caller's bound vault (`ctx.vaultId`); the folder ACL was a single global instance and the JWT carried no vault claim. Any valid token read, wrote, or deleted **every configured vault** by passing `input.vault` — across ~90 tool sites — while `resources/read` was the only surface that already guarded it.

Operator rules:

1. **Store-selector parameter with no store claim in the credential = cross-tenant by default.** Grep tool inputs and request bodies for parameter names that mirror server-side context fields (`vault`, `workspace`, `project`, `org`, `tenant`, `namespace`); for each, check whether dispatch compares `input.X` to a session-derived `ctx.X` or trusts the wire value.
2. **Per-verb guard parity:** when one RPC family (`resources/read`) enforces a binding and its sibling (`tools/call`) does not, the guard exists but was not ported — enumerate every dispatch site, not just the route class that got the security review.

Probe with two disposable vaults and two fake tokens: token bound to vault A calling `input.vault=B` on a read tool, a write tool, and a delete tool, with a vault-A control. A valid finding is one call landing in vault B without any second credential.

### A declined approval is not enforced by the server

On Streamable HTTP with `auth.jwtSecret` set and a client declaring `elicitation.form`, a `destructive: true` tool offered an `inputRequired` confirmation still **wrote after the human answered `{action:"decline"}`**, provided the client re-echoed the validly bound `requestState`. The state token is minted before the elicitation leg, so it proves resubmission belongs to the same call — never that anyone approved it. Fixed in 1.31.4 by additionally requiring the confirm leg's own `inputResponse` to be an explicit accept.

Operator rules:

1. **Drive the confirmation leg yourself.** Against any MCP server with elicitation-based HITL, answer the `elicitation/create` leg with `decline`, `cancel`, a malformed response, and an omission — then resubmit the original call with the echoed state. Every non-accept must render an error and must not be offered a second round for the same declined confirmation.
2. **Gate-family parity:** the dispatch-gated tools were reachable, but sixteen handler-side conditionally gated tools (`write_note` overwrite, `move_note`, …) never read elicitation state on the modern wire at all — neither declines nor approvals passed through. Map gate families separately (dispatch-level vs handler-level) and diff behavior per family per transport (stdio legacy shim vs Streamable HTTP).
3. **Client-driven approval is inherently unverifiable.** The residual in this fix is that a malicious client can still answer its own elicitation with `accept`; a server-owned (legacy shim) confirmation path does not share the gap. Client-driven HITL without server-side accept-requirement is reportable as a design weakness even when the client "behaves."

Prove with an instrumented mock MCP client against a disposable server and a marker-only destructive tool (delete a scratch note). Never use a live vault or trigger real file operations.

### Class confirmations in the same wave

- **Enumeration-only deny lists** (`cvp8`): default configuration was allow-all, `strictReadDefault` was inert, and `.obsidian`/`.git`/`.trash` were denied only during enumeration — not on the direct read path — exposing `.obsidian/plugins/*/data.json` (plugin API keys, Obsidian Sync passwords, vendor-confirmed live repro). Standing probe on any Obsidian-adjacent HTTP/MCP surface: request the control-directory path directly even when listings hide it; deny-decision parity between list and read verbs is the check.
- **Lexical-versus-realpath ACL split** (`c5xx`): read ACL ran on the lexical vault-relative path while containment used realpath, so an in-vault symlink under an allowed glob resolved into a denied folder. Long-standing class (see the July 28 extraction page); noted here as the MCP-server instance. Planting the symlink is out-of-band, so scope reports accordingly.

## Reporting checklist

Include:

- exact product version, commit, deployment mode, and affected route;
- attacker position: remote contact, local process, prompt-influenced agent, anonymous Publish user, or unauthenticated registrant;
- stable identity, mutable/display identity, proxy-added claims, and final authorization input;
- task origin, todo status, pre/post-compression role order, synthetic provenance, and real-user classification;
- raw canonical payload, human-visible approval representation, stored payload, and applied configuration;
- complete allow/deny or role/tool decision tables with negative controls;
- marker-only state changes and a fixed-build comparison;
- source discrepancies, especially unreleased-versus-released version claims.

Keep impact bounded. A display-name collision is not a released-package flaw without revision evidence; a marker reappearing as a user turn is not automatic tool execution; a loopback callback requires local reachability; an incomplete card still requires human approval; an MCP route is only as impactful as the reachable tool set; and a known-ID update path is not ID enumeration unless a separate oracle is proven.
