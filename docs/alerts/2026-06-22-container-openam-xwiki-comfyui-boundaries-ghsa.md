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
