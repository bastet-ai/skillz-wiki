# DB-GPT unauthenticated skill-upload path-to-write primitive

Source: GitHub Security Advisories, 2026-08-26 hourly scan: [GHSA-x75h-xjfp-qrh8](https://github.com/advisories/GHSA-x75h-xjfp-qrh8) / [CVE-2026-80104](https://nvd.nist.gov/vuln/detail/CVE-2026-80104) (critical, unreviewed at scan time). The advisory describes `db-gpt` releases without a published fixed version in the GH record; treat the affected source layout (`packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py`) as the fingerprint until a fixed release is confirmed.

This is a durable, replayable operator chain rather than a one-off advisory: a multipart upload filename crosses an unauthenticated API boundary into a server-side filesystem path, and the only dependency the route declares defaults to an admin-privileged request context. The reusable pattern is **caller-supplied multipart `filename` -> upload-root join with no containment check -> write outside the upload directory**, which is the same family as installer `php_cli_filepath` shells, image-export destination paths, and skill/extension upload handlers found across AI platforms. It matters for red-team work because DB-GPT is routinely deployed as a long-lived, externally reachable agentic data platform, and the write is performed as the server process user.

!!! warning "Authorized validation only"
    Use a disposable DB-GPT instance with a fresh data directory and marker-only target paths. Never plant real credentials, tokens, or executable modules on a live host, overwrite shared application files, or preserve leaked bytes in wiki/report evidence.

## What changed

`skill_upload` in `packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/agentic_data_api.py` takes the request's `file.filename` as given and writes the request body to `upload_dir / filename`. Python path composition with that operator discards the left operand when the right side is absolute and follows parent references otherwise, so a filename such as `../../../tmp/x` or `/tmp/x` resolves outside the intended directory. Nothing canonicalises the result, checks that it remains under the upload root, or prevents a `.py` suffix.

The route's only dependency is `get_user_from_headers` in `dbgpt_serve/utils/auth.py`, which returns a request carrying the admin role whether or not a `user_id` header is supplied. So the endpoint is reachable without credentials: a remote attacker holding no account can write attacker-controlled bytes to any path the server process can write, place a new Python module inside the application package or replace one the application already imports, and obtain code execution in the server process when that module is next imported.

The chain has two trust transitions, each separately testable:

1. **Auth trust** — the header-derived user context grants admin role with no credentials, so the route has no effective access control.
2. **Path trust** — the multipart filename joins into the destination path with no containment, normalisation, or extension restriction.

## Operator triage

1. **Fingerprint the platform.** Identify DB-GPT deployments: the `/api/v1/agentic_data/...` route family, the app's login UI, Docker image labels, and process names. Version fingerprint is the source layout plus route shape; confirm the `skill_upload` handler exists before claiming in-range.
2. **Confirm the auth shape.** Check whether the `user_id` / role headers are actually honoured by other routes on the same deployment. The advisory's described default (admin role without credentials) is the attack precondition; if the deployment layers a real gateway or auth provider in front, the boundary shifts to that edge.
3. **Map the write user.** Impact ceiling is set by the user that owns the server process. A root-run server process turns the file write into root-level persistent access; a scoped user is still an arbitrary file write within that user's writable surface.
4. **Identify import targets for the escalation step.** For the code-execution claim you need a module location the application imports: the installed package directory, an `site-packages` path, or a plugin/skill loader path the app scans on startup.

## Replayable validation boundaries

All of this is validated in an authorized lab with a disposable DB-GPT instance and a synthetic target file. Do not target production deployments, do not plant real credentials or modules on a live host, and do not keep leaked bytes in wiki/report evidence.

### Lab setup

- A DB-GPT instance built from an affected source layout (or the newest release if it still carries the described handler) with a fresh, throwaway data directory.
- A second control instance built from a release or patch where the filename is confined to the upload directory.
- A synthetic target: a marker file path the server process can write (for example a marker under the process user's home, or a sibling of the upload root), plus one import-relevant path (a module name the app loads at startup, in a copy of the package under test).
- No real user accounts, keys, or production data in the instance.

### Auth-boundary check

1. Call the skill-upload route with no headers, then with a synthetic `user_id` header. Record the status and the role the handler resolves. The vulnerable result is an accepted upload in both cases (admin-role context without credentials).
2. Repeat against the control build where a real auth provider gates the route; record the 401/403 decision.

### Path-containment check

1. Upload a benign body (a few hundred bytes of unique marker text) with `filename` set to `<upload_parent>/canary_outside.txt` using relative `../` segments, then again with an absolute lab path.
2. Observe where the bytes land. The vulnerable result is a file created outside the upload directory at the caller-chosen path; the secure result is confinement to the upload root (or a 4xx).
3. Repeat with a filename of the form `sibling_module.py` placed where the app's import scanner looks, but **do not complete the import-to-execution step on any live system**. The lab proof is the marker file landing at the chosen path plus a static record that the path is import-reachable; a code-execution claim requires a separate, isolated demonstration that the module is actually imported at startup.

## Reporting heuristics

- Frame the finding as **unauthenticated header-defaulted admin context -> multipart filename -> upload-root join without containment -> arbitrary file write as the server process user**. State the version/source fingerprint explicitly and note whether a fixed release exists.
- Include, per transition: the exact route, the resolved role with and without headers, the submitted filename, the resolved destination path, and the canary effect (which bytes landed where).
- State the write-user identity explicitly, because it is the difference between "arbitrary file write" and "persistent host access."
- Distinguish the primitive from RCE: the reliable primitive is arbitrary file write; code execution depends on a suitable import target and the process privileges. Do not claim RCE without the isolated import demonstration.
- Keep the auth finding and the path finding separate in the report: even with a real gateway in front, the path-containment gap remains a latent defect; even with auth in place, the filename primitive is reusable by any authenticated low-priv user.

## Safety

- **Authorized, in-scope targets only.** DB-GPT instances are often production AI infrastructure; coordinating with the operator and working in a lab mirror is mandatory.
- **No live credential or module planting.** Never write a real SSH key, token, or executable module to a live host. The lab proof is a synthetic canary at a synthetic path.
- **No destructive overwrite.** Only target marker paths you own in the lab; never overwrite an existing application file on a shared system — if a test requires replacing a module, do it against an isolated copy of the package with no production state.
- **No RCE from the write alone.** The file write is the finding; escalation to code execution is a separate, target-specific step that must be proven in isolation before being claimed.

## October 1 21:3xZ follow-up: second upload route, same product (`python_file_upload`)

[CVE / GHSA-wmgw-w39q-pxgw](https://github.com/advisories/GHSA-wmgw-w39q-pxgw) (9.1, DB-GPT v0.7.5/v0.8.0): `python_file_upload` in `packages/dbgpt-app/src/dbgpt_app/openapi/api_v1/python_upload_api.py` contains **directory traversal letting a remote attacker write files outside the intended workspace/storage boundary** — a second upload-to-write primitive on a *different route family* (`openapi/api_v1/python_upload_api.py` vs this page's `agentic_data_api.py:skill_upload`).

Durable axis: **on any product with a documented upload-traversal fix, enumerate every other route that accepts a filename or path parameter — the fixed handler is the map to its unfixed siblings.** DB-GPT itself now proves the pattern twice on one codebase. Triage step for any AI-platform deployment: `grep -r "UploadFile\|filename\|file.filename" <app>/openapi/` (or the framework equivalent) and record every handler that joins a request-supplied name to a root; test each with the same marker-only containment harness used above (relative `../`, absolute lab path, observed landing path). Never write outside a disposable root; never claim RCE without the isolated import demonstration this page already requires.
