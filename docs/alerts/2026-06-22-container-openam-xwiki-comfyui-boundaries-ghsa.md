# Container build/runtime, OpenAM, XWiki, and ComfyUI boundary checks

Source: hourly offensive-security scan, 2026-06-22. Primary entries: GitHub advisories [GHSA-49p4-px3h-rq49](https://github.com/advisories/GHSA-49p4-px3h-rq49) / CVE-2026-44517, [GHSA-xjvp-4fhw-gc47](https://github.com/advisories/GHSA-xjvp-4fhw-gc47) / CVE-2026-41579, [GHSA-fq9h-c788-fx73](https://github.com/advisories/GHSA-fq9h-c788-fx73) / CVE-2026-44203, [GHSA-c556-q2mh-477v](https://github.com/advisories/GHSA-c556-q2mh-477v) / CVE-2026-44202, [GHSA-2vg8-q4c2-5cw3](https://github.com/advisories/GHSA-2vg8-q4c2-5cw3) / CVE-2026-41573, [GHSA-fhrq-3gmx-p879](https://github.com/advisories/GHSA-fhrq-3gmx-p879) / CVE-2026-44793, [GHSA-w56x-9778-rppx](https://github.com/advisories/GHSA-w56x-9778-rppx) / CVE-2026-44179, and [GHSA-95pq-hr8p-f5g7](https://github.com/advisories/GHSA-95pq-hr8p-f5g7) / CVE-2025-67303.

This batch is durable because the advisories share repeatable operator workflows: remote build contexts crossing outside their approved directory, container images influencing host filesystem setup, identity-provider parameters reaching browser/SSRF/LDAP sinks, wiki title/content markup executing with macro privileges, and AI UI manager configuration exposed through an alternate web-accessible channel.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-49p4-px3h-rq49](https://github.com/advisories/GHSA-49p4-px3h-rq49) / CVE-2026-44517 | Buildah | malicious Git Smart HTTP or tar build context plus `ADD`/`COPY` processing could include files outside the intended build context | Treat remote build contexts as filesystem-boundary tests; prove with disposable outside-context markers and image-layer listings only. |
| [GHSA-xjvp-4fhw-gc47](https://github.com/advisories/GHSA-xjvp-4fhw-gc47) / CVE-2026-41579 | runc with Podman/containerd-style callers | an image with `/dev` as a symlink could steer `setupPtmx` / `setupDevSymlinks` host path operations | Runtime validation should include image-controlled special-directory symlink cases, but evidence should stop at harmless temp host directories and symlink tables. |
| [GHSA-fq9h-c788-fx73](https://github.com/advisories/GHSA-fq9h-c788-fx73) / CVE-2026-44203 | OpenAM OAuth2/OIDC | `response_mode=form_post` rendered the `state` parameter into an OpenAM-origin HTML response | OIDC authorization endpoints need browser-origin canaries for reflected parameters, especially where the IdP renders auto-submitting HTML forms. |
| [GHSA-c556-q2mh-477v](https://github.com/advisories/GHSA-c556-q2mh-477v) / CVE-2026-44202 | OpenAM `/sessionservice` | authenticated session-notification URLs could trigger outbound server-side requests | Session callback, logout, notification, and webhook registration paths should be tested as SSRF surfaces with owned callbacks only. |
| [GHSA-2vg8-q4c2-5cw3](https://github.com/advisories/GHSA-2vg8-q4c2-5cw3) / CVE-2026-41573 | OpenAM CREST REST user/group queries | `_queryId` reached LDAP filter construction with escaping disabled | Identity APIs need LDAP metacharacter controls and blind result-difference tests against disposable users/groups. |
| [GHSA-fhrq-3gmx-p879](https://github.com/advisories/GHSA-fhrq-3gmx-p879) / CVE-2026-44793 | OpenAM SAML2 clustered deployments | federation redirect paths could render user-controlled parameters into OpenAM-origin HTML before authentication under non-default clustered configuration | SAML/OIDC browser-origin checks should include clustered/failover paths and auto-post helpers, not only the main authorization endpoint. |
| [GHSA-w56x-9778-rppx](https://github.com/advisories/GHSA-w56x-9778-rppx) / CVE-2026-44179 | XWiki Pro Macros `excerpt-include` | low-privilege page title and excerpt content were rendered as executable XWiki syntax with macro rights | Wiki macro reviews should track content/title fields that are re-rendered under elevated macro privileges; use inert marker macros, not destructive code. |
| [GHSA-95pq-hr8p-f5g7](https://github.com/advisories/GHSA-95pq-hr8p-f5g7) / CVE-2025-67303 | ComfyUI-Manager | manager config under `user/default/ComfyUI-Manager/` was reachable through ComfyUI web APIs | Exposed AI tooling should be tested for alternate configuration channels that let remote users lower security level or add custom node sources. |

Adjacent AVideo advisories from the same scan were promoted as an update to the existing [AVideo WebSocket/gallery/payment, OpenMeter JSONPath SQLi, and Spree CSV export boundaries](2026-06-04-avideo-openmeter-spree-boundary-batch-ghsa.md#june-22-authorizenet-webhook-and-docker-dotfile-update) page. Older updates to Entire CLI, `http-proxy-middleware`, and CakePHP remain covered by their existing same-day boundary pages.

## Operator triage

1. **Classify the trust boundary before proof.** Build systems, runtimes, IdPs, wikis, and AI dashboards all have different blast radii. The finding is strongest when it names the exact input-to-sink transition.
2. **Use disposable markers.** Outside-context files, temp host directories, lab IdP users, owned callback domains, wiki pages, and fake ComfyUI config keys are enough.
3. **Avoid secret reads and host damage.** Do not read real source files outside a build context, write to host system paths, capture IdP session data, run Groovy/system commands on shared wikis, or modify production ComfyUI manager settings.
4. **Record negative controls.** Include patched versions, route reachability, proxy placement, user namespace/rootless runtime state, and whether the vulnerable feature is enabled.
5. **Prefer side-by-side matrices.** Baseline vs canary requests, allowed vs denied paths, patched vs vulnerable versions, and direct app vs edge route results are clearer than single screenshots.

## Replayable validation boundaries

### Remote build-context containment harness

- Preconditions: an approved lab builder, disposable Git/tar server, and a synthetic outside-context marker such as `/tmp/skillz-build-canary.txt`.
- Serve a normal build context and a canary build context that attempts to reference paths outside the approved directory through archive paths or Git Smart HTTP behavior.
- Build with non-secret context data and inspect only the resulting image layer/file listing for the marker name.
- Positive evidence is marker inclusion or path-resolution logs proving context escape. Do not target SSH keys, CI tokens, source outside the test repo, or host config.
- Negative controls: patched Buildah version, canonical path checks before `ADD`/`COPY`, archive extraction under a temp root, and refusal of absolute or traversal paths.

### Container image `/dev` symlink harness

- Preconditions: a disposable VM, approved runtime testing, and no production workloads on the host.
- Build a lab image where `/dev` is a symlink to a temp directory controlled for the test. Use marker names that cannot collide with real host files.
- Run through the exact stack in scope: Docker, Podman, containerd, Kubernetes runtime class, rootless mode, and user namespace settings as applicable.
- Evidence should be a table showing whether expected hardcoded symlinks (`core`, `fd`, `ptmx`, `stdin`, `stdout`, `stderr`) were attempted or created in the temp directory.
- Do not point the symlink at `/dev`, `/etc`, service config directories, or any path containing real application data.

### OpenAM browser, SSRF, and LDAP harness

- Use a lab realm with disposable users and no production SSO sessions.
- For `form_post`, send paired OIDC authorization requests where only `state` changes from a plain nonce to a harmless DOM marker. Capture the rendered OpenAM-origin HTML and browser behavior in a test profile.
- For SAML2 clustered/failover routes, repeat the same harmless marker approach against the cluster cookie-hash-redirect path only when that non-default deployment mode is in scope.
- For `/sessionservice`, register only owned callback URLs and record method, path, source IP, and nonsensitive headers. Do not target metadata services or internal admin panels.
- For CREST queries, compare `_queryId` baselines with escaped LDAP metacharacter canaries against seeded users/groups. Evidence is result-count or error differences for synthetic identities only.

### Wiki macro privilege harness

- Create two low-privilege lab pages: one excerpt source and one includer.
- Put a harmless marker in the source title and excerpt content that demonstrates whether XWiki syntax is interpreted under macro rights.
- Positive evidence is marker rendering or macro-evaluation output in the includer page; stop before file reads, network calls, process execution, or access to private wiki content.
- Negative controls: title escaping, content rendered as plain text, macro execution under the viewer/page author's rights, and script/programming rights denied to the low-privilege account.

### ComfyUI-Manager alternate-channel harness

- Test only lab ComfyUI instances or explicit program scopes, especially when the service is exposed with `--listen 0.0.0.0` or behind a reverse proxy.
- Attempt to read a synthetic manager config key through the same web API family that can access `user/default/` paths. Then attempt a harmless write to a lab-only setting such as a marker preference.
- If testing custom node source tampering is allowed, use an inert local repository name or owned callback URL; do not install or execute untrusted nodes.
- Negative controls: ComfyUI v0.3.76+ System User Protection API, ComfyUI-Manager v3.38+, config migrated to `user/__manager/`, and security level forced at least `normal`.

## Reporting notes

- Lead with the boundary: **remote build source to local build context**, **image filesystem to host runtime setup**, **OIDC parameter to IdP-origin HTML**, **session callback URL to server-side request**, **REST query parameter to LDAP filter**, **wiki title/content to privileged macro execution**, or **AI manager config path to unauthenticated web API**.
- Keep evidence non-sensitive: file names, path-resolution tables, callback metadata, DOM markers, seeded directory entries, and fake config keys.
- If chaining is approved, state the chain as preconditions plus canary impact. Do not publish exploit payloads that read secrets, modify host files, forge real sessions, or execute commands on shared systems.

### October 8 tracked note: flatpak-builder local-file `file://` source URIs escape build-directory confinement

[GHSA-m6mj-r236-h4v7](https://github.com/advisories/GHSA-m6mj-r236-h4v7) / CVE-2026-107466 (medium): a crafted flatpak build manifest specifies **local file URIs in source download definitions**, the builder bypasses its directory-confinement checks, and host files readable by the build process get incorporated into build artifacts — CI/build-farm info disclosure via a trusted-looking manifest. Same remote-build-context family as this page's Buildah leg (the manifest is the attacker input; the builder's confinement is the boundary). Operator relevance for CI assessments: where a farm builds third-party flatpak manifests, proof stays on a disposable builder with a marker file under `/tmp` and an artifact file listing — never read real SSH keys or CI tokens. Tracked, not promoted standalone (medium, single-axis).

## July 24 OpenAM pre-auth class-loading, deserialization, and consent-rendering follow-up

OpenAM 16.1.2 fixes three adjacent paths:

- [GHSA-wg5r-wc3x-39vc](https://github.com/advisories/GHSA-wg5r-wc3x-39vc) / CVE-2026-62379: default-reachable `/authservice` XML can name a class that `AuthXMLUtils.createCustomCallback` loads and instantiates before authentication.
- [GHSA-gf8h-gq53-288j](https://github.com/advisories/GHSA-gf8h-gq53-288j) / CVE-2026-62263: the WebAuthn serialization filter allows every nested object at depth greater than one, so only an `AuthenticatorImpl` root is constrained and nested classpath gadgets deserialize before assertion verification.
- [GHSA-vqxv-6xrh-49cp](https://github.com/advisories/GHSA-vqxv-6xrh-49cp) / CVE-2026-62280: `display=wap` reaches an OAuth2/OIDC consent renderer missed by the earlier output-escaping fix.

### Marker-only classpath and browser harness

1. Confirm `/authservice` reachability with a normal malformed XML canary and record whether `sunRemoteAuthSecurityEnabled` requires a token. Package version alone is not proof of an externally reachable default path.
2. In a disposable OpenAM JVM, place a custom no-network marker class on the test classpath whose constructor only increments an in-memory counter. Submit an XML callback naming that class and record class-load/constructor counters. Do not use JNDI, process execution, file writes, or third-party gadget classes.
3. For WebAuthn, instrument deserialization and use an `AuthenticatorImpl` root containing a nested synthetic serializable object whose `readObject` increments the same counter. Compare depth one, nested depth, wrong root type, no gadget class, and 16.1.2. Do not generate a weaponized serialization stream.
4. Register a disposable OAuth client, authenticate a lab user, and send paired authorization requests where only `display=wap` and a harmless request-derived DOM marker vary. Capture rendered HTML and marker execution in an isolated browser profile; do not read cookies or invoke account actions.

Report these separately as **unauthenticated XML class name -> constructor**, **allowed serialization root -> unrestricted nested object**, and **alternate consent renderer -> OpenAM-origin DOM execution**. The WebAuthn path still requires a compatible classpath object graph; do not label a deployment exploitable from package presence alone.

## September 16 follow-up: ComfyUI dataset-save folder_name arbitrary write to initializer RCE

[GHSA-xhvx-vf8p-rh4x](https://github.com/advisories/GHSA-xhvx-vf8p-rh4x) / CVE-2026-92816: ComfyUI before 0.30.0 does not sanitize the `folder_name` input on **dataset save nodes**, letting a crafted workflow write attacker-controlled content to arbitrary paths outside the output directory — the advisory's stated escalation is modifying startup files or package initializers (`__init__.py`) for code execution on next load.

Operator checks this adds to the ComfyUI section:

1. **Workflow = config authority.** Any node whose save-path is a workflow string is a containment question. Enumerate every save/export node (dataset save, image save, model save) and diff its path handling; a fixed sibling node does not imply the guard covers all writers.
2. **Lab proof stays inert:** in a disposable ComfyUI, set `folder_name` to a temp relative path that lands next to (not inside) the output dir with a unique marker filename, confirm the write location, then stop. Do **not** write real startup files, site-packages, or shell init on any shared host; the resolved-path table is the finding, not the executed payload.
3. Exposure triage unchanged from this page: instances run with `--listen 0.0.0.0` or behind a proxy without the System User Protection gate put workflow loading — and therefore this sink — within reach of low-trust users.

## September 18 follow-up: XWiki extension-point output closes the enclosing HTML macro → programming-rights Groovy RCE (GHSA-26vp-8gxg-v4pg / CVE-2025-53837)

[GHSA-26vp-8gxg-v4pg](https://github.com/advisories/GHSA-26vp-8gxg-v4pg) / CVE-2025-53837 (critical, CVSS 9.9 `AV:N/AC:L/PR:L/UI:N/S:C`): **any user who can edit their own profile or any document gets arbitrary script macros (Groovy/Python) executing with programming rights** — full read/write over all wiki content. Fixed in XWiki 14.10.2 / 15.0 RC1; the escaping was always missing in XWiki syntax 2, and the profile variant is exploitable back to 3.3 M1.

Mechanism: extension-point renderings are included as content of an enclosing `{{html}}` macro **without further escaping**, so low-privilege content can emit `{{/html}}` and reopen the document in an executing syntax context. The advisory PoC adds an `XWiki.UIExtensionClass` object to a document the attacker can edit (their own profile suffices — no extension-point registration needed) with extension point id `org.xwiki.platform.html.head`, scope "current user", and tilde-escaped payload content (`~{~{~/~h~t~m~l~}~} {{groovy}}…`); opening `/xwiki/bin/view/Main/?sheet=CKEditor.ContentSheet&xpage=plain` then returns the *unclosed* literal `{{/html}} {{cache}}{{groovy}}println(1)…` instead of the evaluated output — the payload survived the html-macro pass as inert escaped text and executes in the outer pass. Other known injection points include `org.xwiki.platform.search.ui.docdoesnotexist` (8.3 M1+).

Operator value this adds to the wiki macro privilege harness above:

- **Macro-close injection class:** whenever renderer output is re-embedded inside a raw-content macro (`{{html}}`, verbatim, code fences), the embedded content can terminate the macro and re-enter the executing syntax layer. This is the second XWiki instance on this page (sibling: CVE-2026-44179 `excerpt-include` re-rendering titles/excerpts under macro rights) — the audit axis is *where rendering output is re-included*, not which field was sanitized.
- **Extension-point registry = sink enumeration surface.** Registered extension points (`org.xwiki.platform.html.head`, search suggestions, etc.) each pull user-editable content into high-privilege page renders. List the extension points on a target and test each one that renders user content into page output.
- **Escape-encoding survives the first pass.** Tilde-escaped macro syntax (`~{~{`) defeats the non-executing containment pass and restores to live macro syntax in the outer pass. For any wiki-syntax validator, test escaped spellings of every blocked macro/sequence, not just the raw form.
- **Privilege math:** low-privilege (self-edit) → programming-rights code execution is a full wiki takeover primitive; the page render of `xpage=plain` sheet endpoints is the trigger, so no victim interaction beyond the attacker's own request.
- Lab proof stays within this page's harness: inert `println(canary)`-style marker macros on a disposable XWiki, positive/negative (patched 14.10.2+) differential on the returned bytes; never run destructive or exfiltrating macros on shared wikis.

## October 3 follow-up: OpenAM 16.1.3 nine-leg pack — legacy SOAP route, PKCE exact-match gating, realm-scoped session ops, and `jwks_uri` fetch (9 GHSAs)

The October 3 15:30Z GHSA wave landed nine OpenAM <16.1.3 advisories. Six carry reusable axes; three are known-class singles folded into the tracked list below.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-45wm-hvw4-223f](https://github.com/advisories/GHSA-45wm-hvw4-223f) / CVE-2026-105115 (high) | Legacy JAX-RPC SOAP interface `/jaxrpc/*` instantiates an attacker-named class from an unverified session identifier — pre-auth classpath probe, crash, potential gadget-chain RCE | Legacy endpoint families survive hardening of the modern surface: enumerate deprecated route prefixes (`/jaxrpc/`, `/identity/`, `/rest/`, `/sessionservice/`, `/authservice/`) separately from the main app |
| [GHSA-mf8f-w84m-x4gc](https://github.com/advisories/GHSA-mf8f-w84m-x4gc) / CVE-2026-105119 (high) | PKCE enforcement applies only when `response_type` is exactly `code`; OIDC hybrid flows (`code token`, `code id_token`, `code token id_token`) issue codes with no bound challenge — intercepted code redeems with **any non-empty** `code_verifier` for a public client | Security controls keyed to an exact-match enum value skip every alternate flow spelling. For any gated protocol parameter, enumerate all accepted values and re-test the control on each |
| [GHSA-55ch-4xvx-7w9q](https://github.com/advisories/GHSA-55ch-4xvx-7w9q) / CVE-2026-105120 (medium) | Sessions REST query: a delegated RealmAdmin supplies a `_queryFilter` naming **another realm** → cross-tenant usernames, universal IDs, session handles | List/query endpoints filter by caller-supplied scope fields instead of the caller's own authorization scope — sweep `_queryFilter`-style parameters with a lowest-privilege delegated admin and a second realm |
| [GHSA-86x4-hjp8-8h99](https://github.com/advisories/GHSA-86x4-hjp8-8h99) / CVE-2026-105121 (medium) | Session destroy checks the **requester's** realm, then acts on the supplied session ID/handle → forced logout of users in any realm by anyone holding `iplanet-am-session-destroy-sessions` | Sibling of the page's standing realm-scope drift: validate scope against the target object, not the caller's context. Destroy/revoke verbs get audited less than read verbs — test both legs |
| [GHSA-r8x8-66rr-q5w2](https://github.com/advisories/GHSA-r8x8-66rr-q5w2) / CVE-2026-105122 (medium) | OAuth2 client registration/modification accepts an unvalidated `jwks_uri`; server-side fetch triggers (client authentication, ID-token validation) are **unauthenticated** → internal/metadata/file probe | Client-registration fields are SSRF sources whose trigger legs are often pre-auth; see the [July 28 webhook/OAuth client trust page](2026-07-28-webhook-oauth-client-trust-boundaries-ghsa.md) for the standing `jwks_uri` axis — prove with owned callbacks only |
| [GHSA-35wg-cp3w-fh5v](https://github.com/advisories/GHSA-35wg-cp3w-fh5v) / CVE-2026-105117 (medium) | Unauthenticated `/json/{realm}/users` `forgotPassword`/`register` accept `subject` and `message` → attacker-worded mail from the org's From address, or `register` as relay to arbitrary recipients | Notification handlers that take body/subject/recipient from the request are phishing-relay oracles — same audit family as the Sept 19 recipient-override axis (`email|recipient|subject|message` params beside unauthenticated action endpoints) |

Tracked from this pack without publication (known classes): [GHSA-wxcf-pvf2-p2h6](https://github.com/advisories/GHSA-wxcf-pvf2-p2h6) / CVE-2026-105116 latent XSS on the cookie-bounce auto-submit page (unreachable — unrelated HTTP 500 blocks exploitation in released versions; re-check only if `cookieHashRedirectEnabled` ships enabled), [GHSA-mxvw-rw3m-5c33](https://github.com/advisories/GHSA-mxvw-rw3m-5c33) / CVE-2026-105118 `endSession` open redirect via unverified `id_token_hint` (open-redirect class), [GHSA-875h-jw66-233j](https://github.com/advisories/GHSA-875h-jw66-233j) / CVE-2026-105114 reflected XSS on the OAuth2 authorize error page (IdP-origin DOM-XSS class, sibling of the June 22 `form_post` leg on this page).

### Harness additions

1. **Legacy-route sweep:** on any IdP/enterprise Java appliance, request each deprecated route family with a malformed minimal payload and compare error shapes to the main app — a distinct stack trace or 500 on `/jaxrpc/*` while the modern routes 401 is itself the fingerprint. Class-instantiation proofs stay bounded to the page's existing marker-class harness (constructor counter in a disposable JVM; no JNDI, no gadget chains).
2. **Flow-spelling matrix for protocol gates:** one decision table per enforcement control — rows = accepted `response_type` values (`code`, `code token`, `code id_token`, `code token id_token`, `id_token`, `none`), columns = challenge bound / verifier accepted / redemption succeeded with empty-vs-any verifier. Run against a disposable confidential+public client pair; intercept codes only between lab clients you own.
3. **Cross-scope delegated-admin probe:** provision the *lowest* delegated admin role in realm A, seed synthetic users/sessions in realm B, then sweep every list/query/destroy verb with realm-B identifiers embedded in filter or ID parameters. Evidence = presence/absence of synthetic session handles and forced-logout of a lab session, never real users.

## October 12 follow-up: flatpak-builder second leg — Git hooks fire on host during patch application — and Blinko plugin-install traversal to root startup-file RCE

### flatpak-builder: `use-git-am` patch application leaves Git hooks enabled (GHSA-rvpr-5p35-6vf8 / CVE-2026-86320, high)

Four days after the tracked `file://` source-URI confinement escape on this page ([GHSA-m6mj-r236-h4v7](https://github.com/advisories/GHSA-m6mj-r236-h4v7), Oct 8 note above), the **same product** lands a second advisory on a strictly worse axis: when a manifest applies patch sources with `use-git-am: true`, flatpak-builder invokes Git **without disabling hooks**, so a malicious source carrying a `.git/hooks/post-applypatch` hook executes **on the host** with the build user's privileges — arbitrary code execution, not just file inclusion. Same-product re-sweep rule validated twice now: when a build-context tool gets one advisory, grep the advisory feed and the source for sibling boundary classes before closing the product.

Operator axes this adds:

- **Git-invoking tools over untrusted input are an execution boundary, not just a fetch boundary.** The untrusted-input-to-`git` class has a known battery: local-clone hooks (this leg, CVE-2024-32002 genealogy), `ext::`/`fd::` remote transports, submodule/alternate-object tricks, and local-path protocols. For any CI/builder that runs Git on attacker-supplied repositories or manifests, test each class separately — a fixed transport leg does not imply hooks are disabled (`git -c core.hooksPath=/dev/null`, `GIT_CONFIG_NOSYSTEM`, `--no-verify` coverage is per-invocation, not global).
- **Builder-side execution class on flatpak CI farms:** on authorized assessments of a build farm that builds third-party manifests, proof stays on a disposable builder with an inert hook that only touches a temp marker file (`touch /tmp/flatpak-hook-canary`), plus a manifest/patch pair you authored; never run hooks that network, read CI credentials, or touch shared cache directories.
- **Manifest trust asymmetry fingerprint:** compare the builder's *download* confinement checks (this page's `file://` leg) against its *apply* step. Validation concentrated on acquisition while apply/patch/extract steps run unsandboxed is the recurring shape — enumerate the pipeline stages, not just the intake validator.

### Blinko through 1.8.8: any-authenticated-user plugin install writes outside the plugin root → root startup-file RCE (GHSA-q62g-66hr-78pq / CVE-2026-108980, high)

The `plugin.installPlugin` tRPC procedure in `server/routerTrpc/plugin.ts` is open to **any authenticated user**, and the install path is built from an unsanitized `name`, so `../` sequences write downloaded plugin files outside the plugins directory. The official Docker image runs as **root**, so overwriting a root-owned startup file yields RCE as root on next start — and self-registration may make the foothold pre-auth. Direct sibling of this page's ComfyUI `folder_name` leg (Sept 16 section): *attacker-controlled write-path string → startup/initializer file → code execution at next load*.

Operator axes this adds:

- **RPC-procedure verb sweep:** tRPC/GraphQL routers hide authorization drift per procedure. Enumerate procedures with install/upload/save/import/export verbs and compare their auth gates against the router default — a procedure-level miss on one install verb is a full chain when the container runs as root. Evidence = resolved-path table from a traversal canary into a temp marker filename, then stop.
- **Container user is the privilege multiplier:** the traversal itself is a common class; what makes it root RCE is the image running as root. Where an app's official image is root-running, every low-severity arbitrary-write finding escalates — check the Dockerfile `USER` directive during recon, before scoring any file-write bug.
- **Self-registration = standing pre-auth ladder:** always test signup on self-hosted tools; if registration is open, "authenticated" gates are effectively unauthenticated, and a low-privilege foothold still reaches root when combined with an unsanitized path parameter.

Lab proof for both legs stays inert: temp marker files, self-authored manifests/hooks, disposable builders/containers, no real startup files, no shared-host execution.

## October 14 follow-up: OpenShift insights-runtime-extractor — privileged scanner execs workload-controlled argv[0] with a half-done privilege drop (98f3/CVE-2026-104795, 8.8)

The Red Hat `insights-runtime-extractor` DaemonSet (`hostPID: true`) forks, `setns()`es into a target container's PID+mount namespaces, `fchdir()`s back through an orphaned FD into its **own** root filesystem (where `/crio.sock` is hostPath-mounted), then calls only `seteuid(target_uid)` — **real UID and saved-set-UID stay 0 and the permitted capability set is retained** — before fingerprinting the workload by running `process.command_line[0]` (argv[0], fully workload-controlled) via `exec.Command(executable, "--version")`. The `check_no_privileged_perms()` guard inspects **only the effective** capability set (so it passes) and is **skipped entirely when the target runs as uid 0**. The executed process can `setuid(0)` to restore full root with `CAP_SYS_ADMIN` and inherits the cwd that resolves into the extractor container holding the **host CRI-O socket** → node-level root.

Durable axes for any privileged scanner/agent inventory (this class generalizes far beyond OpenShift):

- **Privilege-drop completeness is checkable from outside.** `seteuid`-only drops (euid changed, ruid/suid/permitted-capabilities intact) are the fingerprint: a process that *looks* unprivileged to `geteuid`-based guards and to your own `id -u`-style probes still holds `CAP_SYS_ADMIN` and can restore root. Sweep rule on any hostPID/hostPath security agent you're authorized to assess: identify what it **execs or evaluates from workload data** — argv[0], `/proc/<pid>/cmdline`, environ, exe symlink, open FD names — because every such field is attacker-authored the moment one workload on the node is yours.
- **Guards that read only the *effective* set, and guards skipped for root targets, fail in both directions.** The `if uid != 0 { check() }` shape means the *most privileged* targets get *no* check — the exact inverse of a defense-in-depth ordering. Black-box probe: run a workload as root and as non-root and diff whether the scanner's behavior on the root workload is strictly weaker-guarded (it usually is: vendors assume "we don't touch root pods' perms, they're ours" while root pods are precisely where argv[0] spoofing lands).
- **Executed-as-the-workload is the trigger leg.** argv[0] spoof is free: a container whose entrypoint rewrites its own `/proc/self/cmdline` (overwrite argv area) or whose binary is a script named whatever the fingerprint expects makes the scanner run *your* file inside *your* mount namespace with ruid=0. Lab proof stays bounded: single-node kind/minikube cluster with your own DaemonSet copy, marker `--version` script that only writes a temp file, plus verifying which uid/caps the child actually has via the canary itself (`cat /proc/self/status | grep -i cap` into the marker); never against a real cluster's CRI-O socket.
- **Orphaned-FD cwd inheritance** is the quiet cross-container channel: `fchdir()` through an FD opened *before* the namespace switch re-anchors the child in the scanner's filesystem — so "we exec inside the workload's mount ns" still exposes the scanner's own tree (and its hostPath mounts) to the child. Audit shape: any scan loop doing setns/fchdir/seteuid triple — check what the cwd FD points at and whether the executed payload can reach it.

Same wave tracked without publication: JTL-Shop logout-route-before-auth safe-mode toggle DoS ([xvw9 / CVE-2026-103905](https://github.com/advisories/GHSA-xvw9-2xw4-g33x)) — side-effect-before-authentication-check canonical, and same-product unauth arbitrary-consent-name stored XSS in admin consent statistics ([xqfj / CVE-2026-103904](https://github.com/advisories/GHSA-xqfj-gwfj-j97g), 9.3) — unauth-write-into-admin-rendered-page canonical; the JTL same-product re-sweep fires a third time this week (JTL-Connector folded Sept 19 page Oct 14 07:1xZ). Google Cloud Application Integration AuthConfig validation→integration-execution privilege gap / service-account impersonation for authenticated users ([53cj / CVE-2026-85298](https://github.com/advisories/GHSA-53cj-mr2j-j7q8)) tracked for enrichment (vendor says patched, no detail; SA-impersonation-via-config-validation drift worth watching if detail lands). HPE NonStop twelve-leg boilerplate pack, BusyBox dpkg/httpd legs (httpd leg promoted on the [Sept 15 parser page](2026-09-15-http4s-ember-traefik-parser-header-route-boundaries-ghsa.md)), clevis PKCS#11 pin trio (local), unbound DNS RDATA parser quintet (memory-safety class), GStreamer pair, VillaTheme WooCommerce email-template code injection (vuldb sparse), Modern Events Calendar blind SQLi, JetFormBuilder missing-authorization, Complianz public-nonce stored XSS (public-nonce class canonical, Sept 19 page) — all tracked no-publish.

## October 15 22:1xZ follow-up: checkpoint/restore as sandbox-control channel — Podman `run` and containerd CRI both let checkpoint artifacts dictate their own security context (GHSA-2cvf-wqm6-wr9g / CVE-2026-94603 critical, Podman 4.4.0–<5.8.8/<6.1.3; GHSA-p7v4-vr35-mj6f / CVE-2026-95837 high, containerd <2.2.7/<2.3.4, removed 2.4.0)

Two independent projects, one architectural defect, fixed the same week: **checkpoint artifacts are data that configures the sandbox**. Podman `run` silently ignores all user CLI security input (`--cap-drop=ALL`, etc.) when an image carries the annotation `io.podman.annotations.checkpoint.runtime.name`, restoring capabilities from the checkpoint image instead; containerd's CRI `CreateContainer` restore path rebuilds process creds, capabilities, `no_new_privs`, and seccomp **from checkpoint data**, not from the destination `ContainerConfig` — and its status API reports the *requested* config, masking the mismatch from the orchestrator. Root RCE with full caps through a "restrictive policy" pull. Both fixes remove the feature; neither adds validation — the maintainers' judgment was that the channel itself is unfixable. Rootless Podman is unaffected (no C/R support).

- **Image-metadata-as-policy sweep rule (extends the page's flatpak-builder/OpenShift legs):** for any container runtime/tooling, enumerate image **annotations, config labels, and side-artifact formats** that change *how* the container is created — not just what runs. Checkpoint annotations, `io.*` vendor namespaces, and format-detection markers are policy switches an image author flips. Recon command in an authorized lab: `skopeo inspect --raw` / `crane manifest` + config blob dump, grep annotations for anything named checkpoint/restore/runtime; a hostile-registry or compromised-base-image scenario hands you those fields for free.
- **Detection fingerprint for live hosts:** `podman inspect` / CRI container status shows the *requested* security context — Podman and containerd both echo config intent, not restored reality. Truth check from inside the container: `capsh --print` + `grep CapEff /proc/self/status` + `Seccomp:` line vs what the launch policy claims. Any divergence = restored-from-checkpoint state (or a lying status path).
- **Status-reporting-is-not-verification is a durable audit axis:** orchestrators (K8s, kubelet eviction, admission replay) trust CRI status. When a feature's status path reflects the request rather than the kernel state, every upstream control silently no-ops. Generalize to any API that accepts a desired state and reports it back without read-back (device plugins, GPU/IB operators, VM runtimes).
- **Supply-chain angle for hunters:** base images in public registries are the delivery vehicle — scan pulls you run for the checkpoint annotation (vendor workaround explicitly says do this manually), which turns a runtime bug into a repo-level check you can automate in your own pipeline; finding one on a client's CI runner is the report.
