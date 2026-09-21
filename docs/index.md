---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Auth-method precedence + verb-allowlist bypass + ACL tie-break drift (Sept 21)**: Airflow request with **cookie AND bearer** executes + audit-logs as the **cookie's** principal — send two principals at once, diff executing-vs-logged identity (CVE-2026-82355); logout revokes **only the `_token` cookie**, bearer tokens survive for full TTL — replay-after-logout on every credential transport (CVE-2026-86473); count-query missing the row filter → `total_entries` hidden-Dag oracle (CVE-2026-75158). MISP octet: login security controls gated on **POST/PUT only** → any other verb skips bruteforce-block + OTP 2FA + logging (CVE-2026-94379); read-only API key restores full account perms in one call (CVE-2026-94381); `save()` without unsetting client `id` where **sibling loops unset it** → cross-event report reparent (CVE-2026-94374); non-XML-content XML import SSRF + galaxy-name sprintf XSS. + Dogtag **lexicographic ACL tie-break** (wildcard beats specific literal, CVE-2026-80110), Hatchet **empty-`state` sentinel accepted** → login-CSRF (CVE-2026-61687), MINA fix landed on **one branch only** — "fixed" versions still vulnerable (CVE-2026-94301, 9.8) (16 GHSAs)](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md)

- [**Automation-platform credential-test exfil + FQDN-endpoint metadata SSRF (Sept 21)**: AAP Controller Vault plugin `kubernetes_auth()` sends the **controller pod's own SA token** to the URL inside a credential definition when that credential is *Tested* → credential-create role exfiltrates a token with control-plane pod CRUD + secret read (9.6, CVE-2026-12564): every "verify this credential" button that connects out with the platform's identity is an exfil channel. OpenShift Router accepts **FQDN-type EndpointSlice endpoints** → Service proxies to a hostname resolving to cloud metadata, bypassing the prior IP denylist (CVE-2026-42965): IP-parsing validators cannot check names — grep for `net.ParseIP`. Quay `GLOBAL_READONLY_SUPER_USERS` can read **robot tokens for foreign repos** → impersonate any robot (CVE-2026-18255): read-only global roles forget the credential-view sub-resources. + folds: sequoia-openpgp **absent Key Flags subpacket → inferred capabilities → back-signature bypass → signature forge** (CVE-2026-42784) onto the Bouncy Castle crypto-boundary page; RHOAI training-operator **aggregation onto stock `edit`/`admin` roles + PodTemplateSpec passthrough** (CVE-2026-18982/18951), DSPO **weak-PRNG-derived MariaDB/MinIO credentials** (CVE-2026-18611), and DSPO over-scoped ClusterRole post-compromise ladder (CVE-2026-18608) onto the Aug 10 AI control-plane page](alerts/2026-09-21-automation-platform-credential-test-exfil-and-fqdn-endpoint-metadata-ssrf-ghsa.md)

- [**Workflow-platform internal deputies + presigned-URL operation confusion (Sept 21)**: Temporal completion callbacks decide **internal vs external from a caller-supplied `source` header** — non-empty flag makes History re-target the request at the **internal frontend client** (authorizes everything as system admin, no auth), rewriting only scheme+host so your path/query/body ride along → cross-namespace namespace-delete/register/configure; precondition = `internal-frontend.rpc.httpPort` non-zero + `callbacks.allowedAddresses` non-empty (CVE-2026-87858). Temporal's registered **`subprocess` compute provider takes program+argv from the caller's request** and the enable-allowlist check is **skipped when unset (the default)** → namespace-write role → immediate RCE as the server account holding every-namespace persistence creds + cluster TLS (CVE-2026-89139, 1.31.0–1.31.2). NooBaa SigV4 **drops unsigned `x-amz-` headers from the signature calc instead of rejecting** → add `x-amz-copy-source` to a presigned PUT and it becomes server-side CopyObject of anything the signer can read (CVE-2026-94368). Axes: **caller-supplied headers that select internal trust context, default-unset allowlists enforce nothing, presigned URL scope ≠ granted operation**. + CRI-O checkpoint security-state retention fold (CVE-2026-92574)](alerts/2026-09-21-temporal-internal-deputy-subprocess-provider-and-noobaa-presigned-copyobject-ghsa.md)

- [**SAML assertion attack-surface testing (Sept 21 methodology)**: the ToB "SAML is a fractal of bad design" retirement essay inverted into a target-surface map — six layers (XML/DTD, C14N, enveloped signature, conditions, binding parity, identity linking) each an independent parser awaiting a differential; mutation battery order (metadata fingerprint → own-signed canary → XSW family → comment/whitespace c14n family → condition-stripping matrix → per-binding verdict table → Go round-trip asymmetries → two-tenant linking review); the shape-normalization defense inverted as a bypass target (mutate only inside the grammar the normalizer tolerates); report which copy of the document the signature check vs the identity check read](methodology/saml-assertion-attack-surface-testing.md)

- [**REDCap survey-passthrough route confusion → unauth RCE (Sept 20)**: a valid **public survey hash** gates a passthrough router that can reach an **unintended controller route**, and the Data Import handler takes a crafted **file-path/stream parameter** → RCE with no login (CVE-2026-90817, REDCap 13.3.0+). Rule: **a public token authenticates a context, not the internal route family behind it** — sweep route/action selectors from any token-gated passthrough (surveys, share links, form tokens), treat import handlers' path/stream params as file sinks, and check hash enumerability as the precondition-collapse axis](alerts/2026-09-20-redcap-survey-passthrough-route-confusion-unauth-rce-ghsa.md)

- [**Media-pipeline edge surfaces (Sept 20)**: getID3 **shells out with the filename unescaped** → a media file *named* with shell metacharacters runs commands in any embedding PHP app (8.8, CVE-2026-94106) — fuzz filenames, not just contents; getID3 **XXE via XML metadata embedded in a media container** → file read/SSRF with no XML endpoint (CVE-2026-94108); openEQUELLA **FreeMarker SSTI → RCE** through unsandboxed template resolver on author-facing summaries/portlets/MIME templates (8.8, CVE-2026-94109); NivoCart **chunked-upload branch skips the extension validation** the single-file branch runs (`chunks ≥ 2`) → view-only user PHP upload RCE (8.8, CVE-2026-94104). Rule: the upload endpoint's own checks passing is not a negative control — filename sinks, sidecar parsers, template-backed fields, and chunk branches are four extra paths (4 promoted GHSAs + 6 folds)](alerts/2026-09-20-media-pipeline-edge-surfaces-filename-shellout-metadata-xxe-author-template-rce-ghsa.md)

- [**WordPress validation-loop corruption + un-fuzzed transports (Sept 20)**: NextGEN Photo Gallery extension validator **reuses the loop counter as its verdict so the check always passes** → arbitrary web-dir write (CVE-2026-81650) — probe multi-item validators with mixed allowed+forbidden batches; Forminator **XML-RPC deserialization with no class allowlist** (CVE-2026-87067) → give `xmlrpc.php` its own object-injection pass; Forminator quiz import accepts a nested **admin-granting registration form the sibling paths refuse** (CVE-2026-87068) — nesting-parity tables; Unlimited Elements Subscriber POI where the "fix" only raised the reachable role; **SAML SSO ignores the configured linking criterion, always binds by login name** → IdP-assertion ATO up to admin (CVE-2026-82842); TikTok callback redeems attacker-supplied codes with the site's own credentials (11 GHSAs)](alerts/2026-09-20-wordpress-validation-loop-corruption-deserialization-transport-and-assertion-override-ghsa.md)

- [**App-auth forgery + credential-vault platform wave (Sept 20)**: SmartLife/ZTE backends accept **client-runtime-generated app-authentication params as the only authorization** — forge them once and the `verify.serv` email→account-ID oracle + asserted-ID password reset gives full ATO (CVE-2026-86553), while signup registers **any unowned email** without ownership verification (CVE-2026-86552). Devolutions Server: low-priv **connection-definition SSRF** in datacenter discovery leaks other users' credentials (CVE-2026-90971), listing endpoint honors **password-disclosure params without the view-password grant** (CVE-2026-90969), LDAPS/sync clients accept spoofed certs (CVE-2026-13327/84850). HPE SD-WAN Orchestrator: **read-only** role + crafted cache-sync request discloses third-party integration tokens (9.9, CVE-2026-76672)](alerts/2026-09-20-app-auth-forgery-chains-and-credential-vault-platform-boundaries-ghsa.md)

- [**Grammar-desync pair (Sept 20)**: **Exim SMTP smuggling** where the delivered message depends on bytes sent **after a DATA-phase rejection** — matches no transaction sent; test via three-way sent-pre/sent-retry/delivered diff on an owned MTA (CVE-2026-94057). **Expat UTF-16 lone high surrogates consume the following code unit**, hiding `<`/`>`/`&` from one decoder while another assembles markup → XXE batteries must include invalid surrogate sequences on UTF-16 XML inputs (CVE-2026-93990). Rule: buffer/decoder state surviving its kill-boundary. + folds: Argo **NotEquals** field selector dropping cluster-scoped review, Mistral Vibe **`post-checkout` hooks before trust validation**, Exim PROXY-parser memory safety](alerts/2026-09-20-exim-smtp-rejection-smuggling-and-expat-surrogate-markup-hiding-ghsa.md)

- [**JS sandbox-validator + async-render escape wave**: OpenPanel webhook-template validator misses **computed member access to constructor chains** → project-write becomes worker-process RCE (9.9, CVE-2026-93985) — after any template/expression-sandbox fix, enumerate every language alias reaching the same power; ClickHouse **filter-key** SQLi = project-isolation bypass (keys not parameterized); hono/jsx `< 4.13.7` plain strings **unescaped on async composition paths** (`Suspense`/`ErrorBoundary`/`Context.Provider`/`renderToReadableStream`) — escaping is a property of the render path, not the framework (5 GHSAs)](alerts/2026-09-19-js-sandbox-validator-constructor-chain-and-async-render-escape-ghsa.md)

## What lives here



































































## What lives here

- **Skills**: installable, tool-specific guides that agents can execute step by step
- **Recon**: workflows for turning scope into a prioritized asset map
- **Exploit Paths**: concrete attack chains that are specific enough to replay during authorized testing
- **Templates**: reusable report skeletons and delivery formats
- **Notes**: editorial guidance, taxonomy, and source tracking
- **Blog**: short updates when major skills or exploit paths land

Older alert and mitigation-oriented reference pages may remain in the repo, but the primary site surface is intentionally centered on pentesting, red-team, and bug-bounty operator workflows.

## How the skills are written

Each skill page is structured so it can be reused outside the wiki:

- When to use the tool
- Required inputs and prerequisites
- Command patterns worth reusing
- Expected outputs and what to capture
- Safety constraints and scope boundaries

!!! warning "Authorized use only"
    These pages are for lawful research, lab work, and authorized assessments. Do not apply them to systems you do not own or lack explicit permission to test.
