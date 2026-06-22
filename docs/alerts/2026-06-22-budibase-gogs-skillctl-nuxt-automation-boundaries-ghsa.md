# Budibase, Gogs, skillctl, Nuxt, and automation boundary checks

Source: hourly offensive-security scan, 2026-06-22. Primary entries: GitHub advisories [GHSA-jj36-r9w3-3pfh](https://github.com/advisories/GHSA-jj36-r9w3-3pfh) / CVE-2026-50136, [GHSA-v7j5-vc4m-723w](https://github.com/advisories/GHSA-v7j5-vc4m-723w) / CVE-2026-50132, [GHSA-4q6h-8p4v-67vq](https://github.com/advisories/GHSA-4q6h-8p4v-67vq) / CVE-2026-48153, [GHSA-c4v7-xg93-qf8g](https://github.com/advisories/GHSA-c4v7-xg93-qf8g) / CVE-2026-47267, [GHSA-74p7-6h78-gw8p](https://github.com/advisories/GHSA-74p7-6h78-gw8p), [GHSA-mqpr-49jj-32rc](https://github.com/advisories/GHSA-mqpr-49jj-32rc) / CVE-2026-56357, [GHSA-c9cv-mq2m-ppp3](https://github.com/advisories/GHSA-c9cv-mq2m-ppp3) / CVE-2026-56326, [GHSA-9m6g-wc8r-q59c](https://github.com/advisories/GHSA-9m6g-wc8r-q59c) / CVE-2026-48170, and [GHSA-ghmh-jhmj-wcmf](https://github.com/advisories/GHSA-ghmh-jhmj-wcmf).

This batch is durable because each item exposes a repeatable operator workflow around trusted automation boundaries: low-code builders and public routes reaching stored cloud credentials, redirect-following webhook clients bypassing internal-host filters, skill-library metadata steering local filesystem and Git operations, framework navigation helpers normalizing URLs after validation, SCIM patch documents mutating process-global prototypes, and enrollment tokens becoming identity material after database exposure.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-jj36-r9w3-3pfh](https://github.com/advisories/GHSA-jj36-r9w3-3pfh) / CVE-2026-50136 | Budibase S3 attachment URL route | unauthenticated `/api/attachments/:datasourceId/url` requests could generate `PutObject` presigned URLs using stored workspace datasource credentials when the caller knew the workspace and datasource IDs | Low-code reviews should test whether public/static routes can invoke datasource-backed operations without builder/table permissions; prove with disposable buckets and inert object keys only. |
| [GHSA-v7j5-vc4m-723w](https://github.com/advisories/GHSA-v7j5-vc4m-723w) / CVE-2026-50132 | Budibase chat identity handoff | a public, state-changing GET could bind an attacker-controlled Slack/Discord/Teams identity token to an authenticated user's Budibase account without consent or CSRF protection | ChatOps identity-link flows need victim-session and attacker-session separation tests; evidence is a disposable identity mapping, not access to real workspaces. |
| [GHSA-4q6h-8p4v-67vq](https://github.com/advisories/GHSA-4q6h-8p4v-67vq) / CVE-2026-48153 | Budibase OAuth2 validation | builder-supplied OAuth2 token endpoint URLs reached `node-fetch` without the usual outbound blacklist and followed redirects | Builder-controlled integration URLs are SSRF surfaces; prove with owned callbacks and synthetic internal canary services, never cloud metadata or production loopback targets. |
| [GHSA-c4v7-xg93-qf8g](https://github.com/advisories/GHSA-c4v7-xg93-qf8g) / CVE-2026-47267 | Gogs webhook deliveries | webhook URL validation blocked local CIDRs at creation/run time but did not re-check redirect destinations | Git forge webhook clients need post-redirect allowlist checks; prove with an owned redirector and harmless callback target, not metadata endpoints. |
| [GHSA-74p7-6h78-gw8p](https://github.com/advisories/GHSA-74p7-6h78-gw8p) | skillctl 0.1.2 follow-up | committed `.skills.toml`, skill folders, and `--dest` options could steer Git arguments, FIFO/device reads, hardlinks, commit trailers, or outside-root deletion in agent-driven skill workflows | Treat skill libraries as executable-adjacent supply chain inputs; validate with scratch repos, marker files, and inert Git refs only. |
| [GHSA-mqpr-49jj-32rc](https://github.com/advisories/GHSA-mqpr-49jj-32rc) / CVE-2026-56357 | n8n GitHub Webhook Trigger | workflows using the GitHub trigger accepted unsigned POSTs from callers who knew the webhook URL | Automation platforms should verify event signatures before tool/workflow execution; prove with inert fake events that write only to a canary sink. |
| [GHSA-c9cv-mq2m-ppp3](https://github.com/advisories/GHSA-c9cv-mq2m-ppp3) / CVE-2026-56326 | Nuxt `navigateTo` / `reloadNuxtApp` | validation inspected raw paths before browser/WHATWG normalization, and the `open` option skipped script-protocol checks | Redirect and navigation testing should include normalized path, encoded-dot, protocol-relative, and script-scheme parser differentials. |
| [GHSA-9m6g-wc8r-q59c](https://github.com/advisories/GHSA-9m6g-wc8r-q59c) / CVE-2026-48170 | `scim-patch` | SCIM PATCH values containing `__proto__`-style keys polluted `Object.prototype` for the Node process | Identity provisioning endpoints should test JSON patch paths as process-wide object mutation surfaces; prove with same-process canary properties only. |
| [GHSA-ghmh-jhmj-wcmf](https://github.com/advisories/GHSA-ghmh-jhmj-wcmf) | nebula-mesh enrollment tokens | raw enrollment UUIDs were stored in SQLite and could be consumed by whoever read the DB before legitimate enrollment | Post-read identity-boundary reviews should treat pending enrollment tokens like credentials; evidence should stop at synthetic DB rows and canary enrollment attempts. |

Adjacent [GHSA-qc2x-6f54-m6h9](https://github.com/advisories/GHSA-qc2x-6f54-m6h9) was processed but not promoted because the public impact is LAN-local mDNS cache corruption without a specific cross-privilege or data-access workflow. [GHSA-hvqh-jw65-wcpq](https://github.com/advisories/GHSA-hvqh-jw65-wcpq) was processed without promotion as a standalone item because the autocomplete formatter XSS pattern is generic unless tied to a privileged suggestion source. Picklescan follow-up advisories [GHSA-6w4w-5w54-rjvr](https://github.com/advisories/GHSA-6w4w-5w54-rjvr), [GHSA-6556-fwc2-fg2p](https://github.com/advisories/GHSA-6556-fwc2-fg2p), and [GHSA-xp4f-hrf8-rxw7](https://github.com/advisories/GHSA-xp4f-hrf8-rxw7) were processed as additional unsafe-pickle gadget coverage for the existing ML archive-boundary workflow.

## Operator triage

1. **Map who controls each trigger.** Distinguish anonymous public callers, authenticated builders, low-privilege app users, IdP provisioning clients, repository contributors, and holders of leaked database backups.
2. **Separate validation-time from use-time.** For SSRF, redirects, and URL helpers, record whether allowlists run before or after normalization, redirect following, and final request construction.
3. **Use canary-only proofs.** Disposable buckets, owned redirectors, fake chat identities, scratch skill repos, inert webhook events, synthetic SCIM users, and fake enrollment tokens are sufficient.
4. **Avoid sensitive endpoints.** Do not target cloud metadata, production loopback panels, real datasource buckets, real chat accounts, real skill libraries, live workflow side effects, or production enrollment tokens.
5. **Preserve role and topology evidence.** Strong reports show route family, required auth role, datasource/workspace visibility, redirect chain, process owner, and patched-vs-vulnerable comparisons.

## Replayable validation boundaries

### Budibase datasource, chat identity, and OAuth2 harness

- Preconditions: owned Budibase lab or explicit customer scope, disposable workspace, fake S3-compatible bucket, owned chat workspace identities, and one low-privilege builder/user account.
- For signed uploads, create a synthetic S3 datasource with throwaway credentials, then request a presigned URL from a session that should lack datasource access. Upload only an inert marker object to a disposable bucket/key.
- For chat identity handoff, create the attacker-side link token, then visit the handoff URL from a separate disposable authenticated victim browser profile. Evidence is the resulting mapping between two lab identities.
- For OAuth2 SSRF, submit token endpoint URLs pointing to owned callback collectors and owned redirectors. Capture callback timing and validation-envelope behavior only.
- Negative controls: authentication and builder/table permission checks on attachment routes, CSRF/consent on chat-link handoff, URL allowlists applied after redirects, and no response-body leakage from failed OAuth2 validation.

### Gogs webhook redirect SSRF harness

- Preconditions: scoped Gogs instance, disposable repository, permission to create/test webhooks, and an owned redirector domain.
- Create a webhook pointing to the owned redirector. Make the redirector return a 30x to a second owned URL that simulates a blocked host class without using real metadata or internal services.
- Positive evidence is the Gogs server following the redirect and reaching the second canary despite creation-time URL checks.
- Negative controls: redirect disabled or manually handled, final URL host/IP revalidated after every redirect, DNS rebinding resistance, and egress segmentation.

### skillctl hostile library harness

- Preconditions: scratch project, scratch skill library, fake outside-root marker files, and no real credentials or home-directory paths.
- Test `.skills.toml` `source_sha` values that look like Git flags and confirm whether the tool rejects them before invoking `git ls-tree`.
- Add FIFO, device, socket, and hardlink canaries to a malicious skill folder and verify the copy path rejects non-regular files instead of blocking, reading unbounded data, or preserving hardlink relationships.
- Exercise `add --dest` only against temp directories and confirm absolute paths or `..` traversal cannot delete or replace outside-root markers.
- Capture command, version, resolved paths, before/after trees, and rejection messages.

### Automation and identity-parser harnesses

- For n8n, send one unsigned fake GitHub webhook and one properly signed canary event to a lab workflow whose only action writes a harmless marker. Positive evidence is workflow execution without valid `X-Hub-Signature-256`.
- For Nuxt, build a route table covering `/..//host`, `/.//host`, encoded-dot variants, protocol-relative paths, and `javascript:` targets passed through `navigateTo(..., { open })`; capture only redirect locations or blocked decisions.
- For `scim-patch`, apply a PATCH with `__proto__.skillz_canary=true` to a disposable SCIM user in a same-process lab and verify whether unrelated plain objects inherit the marker.
- For nebula-mesh, seed a lab SQLite DB with a pending synthetic enrollment token and show whether reading the DB reveals a consumable raw token; stop before touching real overlay identities.

## Reporting notes

- Lead with the exact crossed boundary: **public route to stored datasource credentials**, **attacker chat token to victim account identity**, **builder OAuth URL to server-side fetch**, **webhook redirect to blocked host**, **skill metadata to Git/filesystem side effects**, **unsigned webhook to workflow execution**, **raw navigation string to normalized browser destination**, **SCIM JSON to process-global prototype**, or **database read to enrollment identity claim**.
- Keep evidence boring and reversible: canary object keys, redirect logs, fake chat IDs, scratch path trees, inert workflow markers, route decision tables, synthetic SCIM properties, and lab enrollment rows.
- Do not include secrets, cloud metadata output, real customer files, real bank/chat identities, live workflow payloads, or production database contents.
