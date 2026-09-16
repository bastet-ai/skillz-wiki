---
title: CI/CD and app-server control-plane trust boundaries: GitLab variable scope, Octopus feed traversal, Ash filter oracle, ZenHive payment dedup
---

# CI/CD and app-server control-plane trust boundaries: GitLab variable scope, Octopus feed traversal, Ash filter oracle, ZenHive payment dedup

A September 16 late GitHub wave (published 2026-09-16T09:30Z) adds four durable devops/app-server operator checks:

- **GitLab EE**: a developer-role user could run a *policy test pipeline* on group projects and read protected CI/CD variables restricted to higher-privileged roles, due to insufficient scope validation — the classic "variable scope is checked on the wrong pipeline type" drift (CVSS 8.5).
- **Octopus Server**: a user permitted to modify non-built-in external feeds could path-traverse to overwrite arbitrary server files, RCE in some configurations — a low-privilege CI/CD write primitive.
- **Ash (Elixir)**: field-policy nil-ing applied to attributes but not to calculations/aggregates, so a forbidden value still acts as a boolean filter oracle — a framework-level authorization-by-implication miss.
- **ZenHive mpp (Elixir payment plug)**: duplicate-submission dedup keyed on caller-supplied raw hex while the deserializer accepts both recovery-id encodings, letting one signed transaction pass the gate twice; plus a paid-response cache leak because the library's `cache-control: private` is overwritten by the mounting app.

Sources:

- GitLab protected-variable scope: [GHSA-4gg6-pm69-gwm2 / CVE-2026-79708](https://github.com/advisories/GHSA-4gg6-pm69-gwm2) (fixed 19.1.8 / 19.2.6 / 19.3.2)
- GitLab adjacent: Markdown JSON-table renderer CSRF (8.2) [GHSA-3xqm-9h96-4cr4 / CVE-2026-78252](https://github.com/advisories/GHSA-3xqm-9h96-4cr4); GraphQL complexity-limit DoS [GHSA-8c2h-q92r-2j66 / CVE-2026-1168](https://github.com/advisories/GHSA-8c2h-q92r-2j66); plus the routine CE/EE patch-tuesday singles ([GHSA-9pgf-qvj2-p23v](https://github.com/advisories/GHSA-9pgf-qvj2-p23v), [GHSA-prpx-9q78-g4hg](https://github.com/advisories/GHSA-prpx-9q78-g4hg), [GHSA-4793-7rmv-288c](https://github.com/advisories/GHSA-4793-7rmv-288c), [GHSA-22cc-9j92-vx92](https://github.com/advisories/GHSA-22cc-9j92-vx92), [GHSA-mvcm-rmq8-7vvx](https://github.com/advisories/GHSA-mvcm-rmq8-7vvx), [GHSA-q86m-h56q-9rjq](https://github.com/advisories/GHSA-q86m-h56q-9rjq), [GHSA-cgh2-rmr4-c8fm](https://github.com/advisories/GHSA-cgh2-rmr4-c8fm), [GHSA-74fm-x674-6p6m](https://github.com/advisories/GHSA-74fm-x674-6p6m))
- Octopus Server: [GHSA-7f5m-mqg8-7jjg / CVE-2026-92355](https://github.com/advisories/GHSA-7f5m-mqg8-7jjg), vendor bulletin [sa2026-09](https://advisories.octopus.com/post/2026/sa2026-09)
- Ash: [GHSA-h9mg-hh48-hrwv / CVE-2026-86338](https://github.com/advisories/GHSA-h9mg-hh48-hrwv)
- ZenHive mpp: dedup bypass [GHSA-p7v4-jpp9-2m3q / CVE-2026-88255](https://github.com/advisories/GHSA-p7v4-jpp9-2m3q); cache leak [GHSA-4h6w-pvrh-g28p / CVE-2026-89186](https://github.com/advisories/GHSA-4h6w-pvrh-g28p)

!!! warning "Authorized validation only"
    Disposable GitLab/Octopus instances, synthetic groups/projects/feeds/users, fake secrets and marker files only. Never read real protected variables, never overwrite files outside a disposable root, never broadcast a real signed transaction, and never serve paid content to third parties as proof.

## GitLab: variable scope is enforced per-pipeline-type, and every alternate pipeline trigger needs its own check

Protected CI/CD variables (protected/release variables) are supposed to reach only runners on pipelines matching the protection rules. The advisory shape: **a developer-role user triggers a policy test pipeline on in-group projects; the test pipeline path skips the scope validation, so higher-privilege-restricted variables are exposed to the developer's job log/artifacts.**

This is a repeat of a durable GitLab audit axis: *each pipeline-creation route (push, MR, web, API, schedule, child pipeline, policy test, merge train) re-declares which variable set it materializes.* On an authorized GitLab engagement:

1. Enumerate every pipeline-trigger route reachable at your current role, including low-visibility ones: policy/test pipelines, `pipeline.create` for protected refs, external-status-check re-runs, and child-pipeline triggers.
2. For each route, run a job that dumps only a *marker-presence* projection (`test -n "$PROTECTED_VAR" && echo present`), never the value. Presence of a variable restricted above your role is the finding.
3. Compare the same variable's presence across pipeline types with one project and two synthetic variables (one unprotected canary, one protected canary restricted to maintainer). A protected variable present in a developer-triggered test pipeline but absent in the developer's normal pipeline proves scope drift without touching real secrets.
4. On the fixed series (19.1.8 / 19.2.6 / 19.3.2), require the negative for every trigger route re-tested — one patched route does not fix the family.

Adjacent GitLab items worth keeping in the methodology: the **Markdown JSON table renderer** record is a state-change CSRF via unsanitized user-controlled data in a renderer — when testing GitLab markdown, include table/JSON-embedded payloads against state-changing endpoints with a second synthetic account, and treat the GraphQL complexity-limit DoS as availability hygiene (tracked, not promoted).

## Octopus Server: feed-modification permission is a server filesystem write primitive

External feeds store package/artifact sources. The advisory: modify a non-built-in external feed → path traversal → arbitrary file overwrite on the Octopus Server → possible RCE. The operator lesson generalizes past Octopus: **any "source/registry/feed" CRUD permission that lets you control a stored name or URI becomes a server-side file operation later** (download, cache, extract, index).

Authorized harness:

1. Two synthetic users: one with only the feed-modification permission, one full admin for the control. Confirm the low-privilege principal genuinely can edit a non-built-in feed.
2. Point the feed at an owned no-content peer first (route-level evidence: does the server fetch? where does it cache?).
3. For the traversal edge, supply only inert traversal-shaped names and record the *canonical proposed write path* from a patched/observed sink or file-existence deltas on a pre-seeded disposable marker — never overwrite a real file to prove the bug.
4. RCE is configuration-dependent per the vendor; treat "arbitrary overwrite reaches a trusted path (plugins, startup directories)" as a separate, explicitly authorized chain step, not an automatic escalation claim.

## Ash: authorization nil-ing must cover every expression node type

Ash's documented guarantee — a field the actor cannot see is replaced by a nil expression in filters, so filters can't be used as read oracles — applied to `Ash.Resource.*` structs but not `Ash.Query.Calculation` / `Ash.Query.Aggregate` structs. Result: `filter(secret_calc == "x")` runs against the real value, and row-match/no-match responses recover the forbidden value bit by bit.

Reusable checks for any framework with attribute-level authorization:

1. Build the expression-node inventory: attribute, association path, calculation, aggregate, fragment, expression, literal. Test a forbidden value through **each node type** as a filter predicate, not just plain attributes.
2. Prove with a boolean-observable predicate against one known synthetic row (match/no-match differential), never bulk extraction.
3. Generalize beyond Ash: GraphQL/ORM layers that redact fields in *selections* but pass them through *filters/order/aggregates* are the same class (cf. the existing field-masking differential patterns).

## ZenHive mpp: dedup keying, transaction malleability, and library-vs-app header authority

Two Elixir payment-library edges with general applicability:

- **Reserve-key malleability**: the duplicate-submission gate keys on the caller-supplied raw hex (`tx.raw`) while the deserializer accepts both recovery-id encodings (`v=27` and `v=0`), so one signed transaction passes the gate twice via two byte representations; the post-broadcast mark uses the *canonical* hash the reserve never reads. Audit rule: any replay/dedup/idempotency gate must be keyed on the **canonicalized** form the business logic consumes, and tested with equivalent-representation pairs (case, encoding variants, normalization aliases) — not just byte-identical replays.
- **Library guarantee defeated by the consumer**: the payment plug sets `cache-control: private` *before* the wrapped app runs; `put_resp_header` replaces, so an app setting its own `cache-control: public` on the paid route silently voids the protection, and a shared CDN caches the paid response — receipt and all — for unpaid clients. Audit rule: prove trust guarantees **through the full response chain** (app → proxy → cache), not at the library boundary; headers set pre-handler are advisory, and a `register_before_send`-style last-write authority is the correct shape. Also note the receipt-on-error variant: verify that success-only artifacts are stripped from non-2xx final responses.

## Reporting notes

- For GitLab, report trigger route × variable-scope as a matrix with presence-only projections; never include variable values.
- For Octopus, state the exact permission held, feed type, canonical write path, and whether RCE configuration (trusted path reachable) was independently confirmed or left as vendor-stated possibility.
- For Ash and ZenHive, the finding is the boundary drift (node-type miss, representation-keyed gate, overwritten guarantee header), demonstrated by differential response or recorder evidence; do not escalate to "data breach" or "double spend" without the downstream sink proven in an owned environment.
