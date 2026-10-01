# Agent tooling, AI-platform, and dev-console unauth boundaries: unauth TCP command RCE, unauth API-to-DB SQL relay, OAuth email-collision session mint, env-gated auth skip, and `trust_remote_code` model-load RCE (GHSA)

Source: hourly offensive-security scan, 2026-09-05 GitHub advisory `unreviewed` wave (published 09:30–12:31 UTC batch). Durable because the wave spans three repeatable operator axes this wiki already carries — **unauthenticated execution on agent/LLM infrastructure**, **unauth API-to-DB / URL relay (SQL + SSRF)**, and **session minting without identity proof** — plus a model-loading `trust_remote_code` default axis. Each is a distinct trust boundary, but the audit pattern is the same: caller-controlled input crosses from "input" to "server-side execution authority" with no identity or network gate.

Primary entries:

| GHSA | Product | Boundary | Defect | Severity |
| --- | --- | --- | --- | --- |
| [GHSA-vmh4-qv5g-wc55](https://github.com/advisories/GHSA-vmh4-qv5g-wc55) / CVE-2026-86124 | AutoAgent | unauth TCP command RCE | the agent's communication TCP server binds all interfaces and executes attacker-supplied bash as root; bind-mounted host workspace directories become host-adjacent | critical |
| [GHSA-pccw-h89v-h9cj](https://github.com/advisories/GHSA-pccw-h89v-h9cj) / CVE-2026-86121 | Cua `computer-server` | env-gated auth skip + unauth command/file/PTY | when `CONTAINER_NAME` is unset the server skips authentication, binds all interfaces, and exposes `run_command`, arbitrary file read/write, and interactive PTY on TCP 8000 | critical |
| [GHSA-7xvg-gx2w-r5cc](https://github.com/advisories/GHSA-7xvg-gx2w-r5cc) / CVE-2026-86123 | SQL Chat | unauth API-to-DB SQL relay | four unauthenticated endpoints accept client-supplied connection parameters and run arbitrary SQL against attacker-specified hosts → internal-DB access + pivot | critical |
| [GHSA-rchm-727g-v36m](https://github.com/advisories/GHSA-rchm-727g-v36m) / CVE-2026-86117 | Coolify | OAuth email-collision session mint | the OAuth callback signs the caller into an existing account based only on email address, without verifying provider assertions or binding the OAuth identity — register the victim's email on any enabled provider to mint their session | critical |
| [GHSA-57g9-xg4g-rmpp](https://github.com/advisories/GHSA-57g9-xg4g-rmpp) / CVE-2026-86169 | Axolotl | `trust_remote_code` model-load RCE | the multipack patch path defaults `trust_remote_code` to `None` (not `False`), and `AutoModelForCausalLM.from_pretrained` loads a caller-selected `base_model` Hugging Face repo with hardcoded `trust_remote_code=True` | high |
| [GHSA-w6m8-h8j4-89w4](https://github.com/advisories/GHSA-w6m8-h8j4-89w4) / CVE-2026-86173 | MindsDB | unauth crawler-URL SSRF | the web-crawler handler fetches caller-controlled URLs (`CrawlerTable.list`) with no allowlist when the config is the default empty value → internal/cloud-metadata reach | high |
| [GHSA-474j-x27j-w5wx](https://github.com/advisories/GHSA-474j-x27j-w5wx) / CVE-2026-86119 | Webstudio | unauth proxy-route SSRF | `/cgi/image`, `/cgi/video`, `/cgi/asset` proxy routes accept arbitrary URLs and read cloud metadata / internal services when `RESIZE_ORIGIN` is unset | critical |
| [GHSA-jmxm-qmrf-xrpp](https://github.com/advisories/GHSA-jmxm-qmrf-xrpp) / CVE-2026-86122 | Rowboat | authenticated MCP/webhook URL SSRF | custom MCP-server and webhook URLs are not validated, letting an authenticated user point them at internal services / metadata | medium |
| [GHSA-vfc8-q896-v58j](https://github.com/advisories/GHSA-vfc8-q896-v58j) / CVE-2026-86115 | Sim | URL-prefix internal classification SSRF | tool requests are classified "internal" by URL prefix without scheme normalization, skipping SSRF validation and minting internal auth tokens (`/api/...` paths reach `POST /api/function/execute`) | medium |

!!! warning "Authorized validation only"
    Keep proofs to disposable lab instances, synthetic agents/workspaces, owned no-content peers, and denied network/file/process/DB sinks. Prove unauth RCE with one inert canary command that writes a marker; do not execute real payloads, read host/credential files, or touch a bind-mounted real workspace. Prove SQL relay and SSRF against your own lab DB / owned callback listeners — never cloud metadata, RFC1918 production hosts, or internal services you do not own. Prove the OAuth boundary with disposable synthetic users on a lab IdP; do not target real user accounts or a live production IdP.

## Boundary map

| Product | Input | Trust break | Reusable check |
| --- | --- | --- | --- |
| AutoAgent | raw TCP bytes to the agent port | no auth on a root-capable command sink | Connect to the exposed port; send one inert command; record whether it runs and whether the cwd is a bind-mounted host path. |
| Cua `computer-server` | `run_command` / file / PTY endpoints | auth is gated on an env var that is unset by default | With `CONTAINER_NAME` unset, hit TCP 8000 unauthenticated; record command/file/PTY access. Then set the env var and re-test (negative control). |
| SQL Chat | connection parameters to the four API endpoints | no auth + caller-chosen host/credentials | Point the relay at a lab DB you own; run one `SELECT`/schema-enumeration query; record host+DB chosen by the caller with no credential of the server's. |
| Coolify | OAuth callback email | identity = email string, not a verified provider assertion | Register the victim's email on a lab IdP; complete the OAuth flow; record whether a session for the victim account is minted without their password/2FA. |
| Axolotl | `base_model` repo selection | `trust_remote_code` guard bypassed by `None`→`True` | Select a lab-owned HF repo with inert `auto_map` code; record whether the loader executes `trust_remote_code=True`. |
| MindsDB | `CrawlerTable.list` URL | default-empty allowlist = no fetch gate | Drive the crawler at an owned callback URL and at a synthetic denied destination; record which are fetched. |
| Webstudio | `/cgi/{image,video,asset}` URL | proxy route has no network gate when `RESIZE_ORIGIN` unset | Drive the proxy at an owned listener and a synthetic denied host; record the final dialed destination. |
| Rowboat | custom MCP/webhook URL | authenticated-but-unvalidated destination | As a synthetic user, point a custom MCP/webhook URL at an owned listener; record whether the server dials it. |
| Sim | tool-request URL path | prefix match without scheme normalization skips SSRF validation | Supply a path starting with `/api/` inside an HTTP block; record whether SSRF validation is skipped and an internal token is minted. |

## Replayable validation boundaries

### AutoAgent unauthenticated TCP command RCE

1. Stand up a disposable AutoAgent instance (vulnerable build) with its communication TCP port reachable only from your lab network.
2. Connect to the port and send one inert command (e.g. write a fixed marker to a temp path); record whether it executes and as which user.
3. Confirm the execution context: does the process run as root, and does its cwd resolve to a bind-mounted host workspace?
4. Negative control: the fixed build, and/or the same instance with the port firewalled / bound to loopback.

Report as **exposed agent TCP port -> unauthenticated root shell**, naming the port and the bind-mount boundary. Do not execute real payloads, read host credentials, or touch a real bind-mounted workspace.

### Cua `computer-server` env-gated auth skip

1. Provision a disposable Cua `computer-server` (`< 0.3.42`) with `CONTAINER_NAME` unset and the port reachable from the lab.
2. Unauthenticated, exercise `run_command` with one inert canary, one file read/write against a marker, and one PTY connect; record which succeed.
3. Negative control: set `CONTAINER_NAME` and repeat — authentication should now gate the same endpoints.
4. Report the exact env gate and the default bind (all interfaces). Do not read real files or credentials.

### SQL Chat unauthenticated API-to-DB SQL relay

1. Deploy a disposable SQL Chat with one lab SQL database you own.
2. Unauthenticated, call one of the four relay endpoints with connection parameters pointing at your lab DB; run one `SELECT` and one schema-enumeration query.
3. Record: the host/credentials chosen by the caller (not the server's) and the returned rows.
4. Do not point the relay at internal, cloud, or production databases; do not run DDL/DML against anything you do not own.

### Coolify OAuth email-collision session mint

1. Provision a disposable Coolify (`<= 4.3.17`) with one lab IdP enabled and two synthetic users (attacker, victim) who share no session.
2. Register the victim's email address on the lab IdP; complete the OAuth flow as the attacker identity.
3. Record whether the callback mints an authenticated session for the victim's Coolify account without their password/2FA.
4. Negative control: the fixed build, and a flow where the provider assertion is actually verified. Do not target real user accounts or a live IdP.

### Axolotl `trust_remote_code` model-load RCE

1. Create a lab-owned Hugging Face–compatible model repository whose `auto_map` / config points to inert code that writes one marker.
2. In a disposable Axolotl run (`<= 0.18.0`), select that repo as `base_model` through the multipack patch path.
3. Record whether the loader executes the `auto_map` code (i.e. `trust_remote_code=True` in effect) and the marker write.
4. Negative control: a repo with no `auto_map`, and the fixed build where `trust_remote_code` defaults to `False`. Do not load untrusted code on a production worker or a shared model cache.

### MindsDB / Webstudio / Rowboat / Sim URL-relay (SQL-adjacent SSRF) family

For each, the shape is the same — a caller-controlled URL (or DB target) reaches a server-side fetch with no allow/deny gate:

1. Stand up the vulnerable component with network limited to your owned listeners.
2. Drive the fetch/relay at (a) an owned callback URL and (b) a synthetic "denied" destination (your internal listener). Record which are reached.
3. For **Sim**, additionally supply a path beginning with `/api/` in an HTTP block and record whether SSRF validation is skipped and an internal auth token is minted.
4. For **Rowboat**, use a synthetic authenticated user and point a custom MCP/webhook URL at an owned listener.
5. Do not fetch cloud metadata, RFC1918 production hosts, or internal services you do not own.

## Durable operator value

1. **Agent/LLM infrastructure ships root-capable ports with no auth by default.** AutoAgent and Cua both expose command sinks (bash / `run_command` / PTY) that are either unauthenticated outright or gated on an env var that is unset in a default install. The reusable recon check: *enumerate an agent's listening ports, probe each for an unauth command/file/PTY sink, and note whether the auth gate is a config default rather than an enforced identity check.*
2. **"Relay" APIs turn an unauth endpoint into an internal pivot.** SQL Chat, MindsDB, Webstudio, Rowboat, and Sim all let a caller pick the *destination* (a DB host, a URL, an internal path) with no identity or network gate. The reusable pattern: *identify caller-controlled destination fields on any unauth/authenticated API and test whether the server reaches a destination the caller chose* — this is the SQLi-adjacent SSRF class, and it frequently skips the allowlist when the config is empty by default.
3. **Email is not identity on an OAuth callback.** Coolify's email-only match means anyone who can register the victim's email on *any* enabled provider can mint the victim's session. The reusable check for every OAuth/SSO callback: *does the handler verify the provider assertion and bind the provider subject, or does it only compare an email string against an account?*
4. **`trust_remote_code=None` is `True` in disguise.** Axolotl's guard defaults `trust_remote_code` to `None`, and the loader hardcodes `True` for the caller-selected base model. The reusable check for any model-loading path: *trace `base_model`/`model_name` to the `from_pretrained`/`load` call and record the effective `trust_remote_code` value* — a `None`/absent default is the failure, not an explicit `False`.
5. **URL-prefix "internal" classification without scheme normalization is an SSRF bypass.** Sim's prefix match (`/api/...`) skips the fetch gate and mints an internal token. The reusable check: *feed the same path with different schemes/encodings and record whether the SSRF decision flips.*

## Processed without promotion from the same wave

The 2026-09-05 09:30/12:31 unreviewed batch also included product-specific WordPress plugin XSS/priv-esc/authorization entries (Pods, Abandoned Cart Pro, EmbedPress, Unlimited Elements, HT Menu, King Addons, Bold Page Builder, CatFolders, Kirki, JCH Optimize, Contact Form by Supsystic, Eventin, Joli TOC, VikWidgetsLoader, FooGallery, Events Calendar, Custom Contact Forms, Ninja Forms Save Progress, Nokri theme, LearnDash, Mail Mint) and single-product authorization/IDOR findings (NetBox, BookWyrm, Arcane, APITable, gonic, Metabase, Pterodactyl, Plane, Pixelfed, Lara Dashboard, ugrep, CDT, Bilibili Desktop). These were marked processed without publication because they do not add a distinct operator workflow beyond the boundaries above; the reusable checks are already covered by this page's axes and the existing WordPress identity/token-boundary pages.

## October 1 follow-up: DeepWiki-Open `/codemap/file` — containment check keyed on input *shape*, unauthenticated absolute-path read (folded)

- **DeepWiki-Open through commit d92819a unauthenticated arbitrary file read** ([GHSA-2p6v-qgww-hch5 / CVE-2026-103591](https://github.com/advisories/GHSA-2p6v-qgww-hch5), high): `GET /codemap/file` takes a `repo_url` parameter; the path-containment logic only applies when the value **parses as a URL/repo identifier** — supplying a *non-URL* value skips the containment branch entirely and the absolute path is read straight off disk, disclosing any file the API process can open. An AI-wiki/code-indexing tool (which routinely holds repo clones, API keys, and cloud credentials on disk) reachable unauthenticated.
- Durable axes: (1) **containment validators keyed on input shape fail-open on shape mismatch** — if the sanitizer's first branch is "is this a URL / is this a repo slug / does this match pattern X," the *non-matching* branch often goes straight to the sink unchecked. Test every path/URL dual-purpose parameter with values deliberately outside each accepted shape (absolute paths, `file:`-less paths, drive letters, UNC) and record which branch your input took. (2) This is the read-side twin of the page's caller-controlled-destination relay rule: *the same parameter that selects a remote repo selects a local file when you change its spelling.* On any DeepWiki-Open-style deployment (attacker-visible AI code-indexers are becoming common in OSS self-hosting), probe `/codemap/file?repo_url=/etc/passwd`-shaped canaries as a first-touch unauth check, reading only synthetic marker files you placed, never real credentials.
