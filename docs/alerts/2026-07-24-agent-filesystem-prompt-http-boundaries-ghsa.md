---
title: Agent, filesystem, prompt, and HTTP boundary checks from late July 24 advisories
---

# Agent, filesystem, prompt, and HTTP boundary checks from late July 24 advisories

A late GitHub advisory wave yields durable operator checks for fail-open agent policy, recurring-fetch SSRF, watch-stream authorization, path containment, local prompt rendering, shell-context escaping, JSF resource/channel trust, and HTTP parser differentials.

Sources: [GHSA-8q49-2h5h-434x](https://github.com/advisories/GHSA-8q49-2h5h-434x), [GHSA-xg4h-6gfc-h4m8](https://github.com/advisories/GHSA-xg4h-6gfc-h4m8), [GHSA-3r53-75j5-3g7j](https://github.com/advisories/GHSA-3r53-75j5-3g7j), [GHSA-6xj8-qv9j-xcjq](https://github.com/advisories/GHSA-6xj8-qv9j-xcjq), [GHSA-fwjx-9p69-h25h](https://github.com/advisories/GHSA-fwjx-9p69-h25h), [GHSA-fp43-vj7g-pg92](https://github.com/advisories/GHSA-fp43-vj7g-pg92), [GHSA-w4hw-qcx7-56pr](https://github.com/advisories/GHSA-w4hw-qcx7-56pr), [GHSA-29w2-fq35-v728](https://github.com/advisories/GHSA-29w2-fq35-v728), [GHSA-86cx-wwf4-phq4](https://github.com/advisories/GHSA-86cx-wwf4-phq4), [GHSA-p6ph-3jx2-3337](https://github.com/advisories/GHSA-p6ph-3jx2-3337), [GHSA-95cv-r8x4-vh75](https://github.com/advisories/GHSA-95cv-r8x4-vh75), [GHSA-46q4-43ph-c6fr](https://github.com/advisories/GHSA-46q4-43ph-c6fr), and [GHSA-mhvj-jhpq-885v](https://github.com/advisories/GHSA-mhvj-jhpq-885v).

!!! warning "Authorized validation only"
    Use disposable agents, owned callbacks, synthetic keyspaces/files, inert repositories, lab browsers, and one-connection HTTP fixtures. Never invoke production cloud operations, query metadata/internal services, read another tenant's files, run attacker-controlled prompt commands, or test desynchronization against shared users.

## Agent startup and recurring-fetch controls

### AWS API MCP Server policy initialization

Versions `0.2.13` through `1.3.46` could continue serving when optional security-policy data failed to initialize. The per-request gate was then skipped for the process lifetime, although the attached IAM principal still bounded AWS actions. Version `1.3.47` is the fixed control.

Build a local or disposable server with fake credentials and one inert MCP operation. Compare:

1. policy loads and permits the canary;
2. policy loads and denies the canary;
3. policy data is unavailable at startup;
4. policy becomes unavailable after a successful startup; and
5. fixed-version startup under the same failures.

Positive evidence is **policy initialization failure -> server remains ready -> operation denied by configured policy becomes callable**, captured with readiness logs and an inert tool marker. Do not call a real AWS API or interpret IAM denial as proof that the MCP policy ran.

### FrontMCP OpenAPI polling SSRF

In `@frontmcp/adapters` through `1.5.5`, the initial OpenAPI URL load used the guarded loader, but `OpenApiSpecPoller` later fetched the same URL with raw global `fetch()`. Exposure requires URL-based configuration, `polling.enabled: true`, and an attacker-influenceable URL or host. Version `1.5.6` routes recurring polls through the same URL policy.

Use an owned redirector and two owned listeners representing the permitted and synthetic-denied destinations. Record the initial-load decision, polling decision, redirect-hop decision, DNS answer used for validation, dial destination, and callback nonce. A strong proof shows **initial URL rejected or pinned -> recurring poll independently fetches -> owned denied listener receives GET**. Do not use cloud metadata, RFC1918 production hosts, or uncontrolled DNS rebinding.

## Authorization and filesystem tuple checks

### etcd exact-key grants versus open-ended watches

In etcd before `3.5.33`, `3.6.14`, and `3.7.1`, a principal with READ permission on one exact key could issue a Watch request with an open-ended `range_end` (`WithFromKey`) and receive events for lexicographically later keys. Range/Get and DeleteRange are not the reported paths.

Create a lab keyspace with `/team/a/allowed` and later-sorting synthetic deny keys. Grant only the exact allowed key, then compare exact-key Get, exact-key Watch, bounded-prefix Watch, and open-ended Watch. Preserve key names and canary values only. Report **exact-key READ grant -> open-ended Watch interval -> event outside authorized interval**; never point the client at Kubernetes backing etcd or collect Secrets.

### OpenList base-path and batch-rename boundaries

OpenList through `4.2.3` exposes three related but distinct checks; `4.2.4` is the fixed control:

| Surface | Boundary | Safe proof |
| --- | --- | --- |
| Share creation | raw `HasPrefix` treats `/base2` as a descendant of `/base`, then stores a share target consumed without rechecking creator scope | Create `/base` and `/base2` under disposable storage, put one marker in the sibling, and prove only marker-share listing/download. |
| Bleve search | sibling-prefix results pass a raw path-prefix check, while backend `Total` can count globally before authorization filtering | Seed unique marker names in both directories and compare returned marker metadata and count. Do not infer file content from a count oracle. |
| Batch rename | `src_dir` is authorized before attacker-controlled `src_name` is appended and normalized; only `new_name` received relative-path validation | Rename one sibling marker to another inert name, record pre-normalized and canonical paths, then restore it. |

Keep the tuple explicit: **authorized base, requested parent/source directory, child/source name, canonical target, operation**. Do not target application files, credentials, other users, or non-reversible storage operations.

## Repository and runtime text boundaries

### Oh My Posh path templates and terminal controls

Oh My Posh through `29.35.0` re-parsed a path containing literal directory names as a Go template with command-capable functions; it also emitted control bytes from directory names and Git metadata into the terminal. Version `29.35.1` is the fixed control.

Test in a disposable shell profile and repository with no credentials or hooks:

- create a directory name containing template delimiters that increments an in-process recorder or writes one nonce under the temp root,do not execute a shell payload;
- create a commit subject containing harmless title-change or visibly escaped control-byte markers,do not write the clipboard;
- render the prompt without opening an interactive production terminal, and preserve raw output bytes plus marker state;
- compare path styles and a Git segment only when each is actually enabled by the tested theme.

Report the two roots separately: **literal filesystem component -> second template evaluation -> inert function effect** and **repository/path text -> prompt bytes -> terminal control interpretation**.

### Quasar deep merge and Shescape CMD grammar

Quasar `extend(true, ...)` through `2.21.4` allowed `__proto__`, `constructor`, and `prototype` keys to cross a deep merge into process-global prototypes; `2.22.0` is the fixed control. Require an application path that places attacker-controlled object keys into the exported deep-merge helper. In a fresh process, use one inert property, snapshot before/after state, exercise one real downstream policy lookup, clean up, and repeat on the fixed version. Do not claim code execution from pollution alone.

Shescape before `2.1.14`, and `3.0.0` before `3.0.1`, mishandled parentheses in Windows CMD command contexts. Reproduce only in a disposable Windows VM with an argv/branch recorder and a command whose sole effect is a temp marker. Capture shell selection, original command grammar, escaped value, parsed branch, and patched result. This is context-dependent **untrusted value -> escaping helper -> surrounding CMD grammar changes control flow**, not universal shell injection. The adjacent Dash/Zsh path-disclosure and resource-exhaustion reports are not promoted as standalone operator workflows.

## OmniFaces resource, browser, and channel boundaries

[GHSA-fp43-vj7g-pg92](https://github.com/advisories/GHSA-fp43-vj7g-pg92) combines several independently reachable surfaces. Fixed releases are `1.14.3`, `2.7.33`, `3.14.23`, `4.7.12`, and `5.4.2`.

- **Combined resources:** require the combined-resource handler, and separately establish wildcard-CDN, excluded-resource, or dynamic graphic-handler reachability. Use a short structurally valid forged ID, a synthetic `.xhtml` marker, an owned CDN callback, and a canary `Host`. Do not use decompression/cache growth as the proof.
- **`o:hashParam`:** require a page using the component and a follow-up Ajax render. Use a harmless DOM dataset/counter marker to show URL-fragment text crossing into callback JavaScript; do not capture sessions.
- **Push channels:** use two disposable browser sessions and a disclosed synthetic session/view channel UUID. Prove only whether a cookie-less second client can subscribe and receive one marker event. The UUID is a bearer prerequisite, not a brute-force target.

Keep claims separate: forged resource IDs do not automatically prove arbitrary SSRF; `HashParam` retention is not execution without the Ajax sink; and channel replay requires prior channel-ID exposure.

## http4s blaze request boundaries

Two blaze advisories affect default `BlazeServerBuilder` HTTP/1.1 handling through `0.23.17` and milestones through `1.0.0-M41`; fixed controls are `0.23.18` and `1.0.0-M42`.

- The wire parser accepted multiple malformed framing forms that can disagree with a front-end parser. Exploitability requires a specific intermediary pair; package presence alone is not request smuggling.
- Chunked trailer fields could be promoted into `Request.headers`, potentially restoring a proxy-stripped `X-Forwarded-*` or synthetic internal-auth field.

Use a disposable front end, blaze origin, two harmless routes, and one TCP connection per fixture. Capture the exact request bytes, front-end boundary/headers, origin boundary/headers, response sequence, and fixed-version result. For trailers, send a canary trust header both in the initial header block and trailer, with the front end configured to strip the initial copy; prove only marker-route selection. For parser cases, stop at a second canary route or response-order delta,never target another user's request, cache entry, or authenticated session.

## Reporting checklist

- State the exact version, feature flag, role, and deployment precondition.
- Preserve both raw and canonical forms: URL validation versus dial, base path versus resolved path, exact grant versus watch interval, escaped text versus shell grammar, and front-end versus origin bytes.
- Use fixed-version negative controls and a baseline that exercises the intended feature.
- Name the narrow transition proven; do not inflate canary evidence into cloud compromise, cross-tenant document theft, arbitrary RCE, or generic request smuggling.
