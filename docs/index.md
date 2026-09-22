---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Guard verdict vs sink copy — Dancer2 four-GHSA cluster (Sept 22)**: Dancer2 <2.2.0: `headers_to_array` strips CR/LF from header **values but not names** → a request-derived header name carrying CRLF = response splitting (CVE-2026-93711); a dying `before` hook's refusal **still runs the route body and its writes** when the exception handler halts via the keyword instead of the response object — the caller sees a refusal the server never enforced (CVE-2026-93710): on every hook/middleware-enforced gate, build a response-status-vs-side-effect fidelity table; AutoPage guard compares the path **as text** while the lookup canonicalizes → `//`, dot segments, `%2f`, case variants escape it (CVE-2026-93709); File handler joins **uncollapsed `..`** onto `public_dir`, checks only "readable regular file" → unauth `config.yml` read, but only once `static_handler: 0` — **config posture is the precondition probe** (CVE-2026-93712). + fold: Python stdlib `tarfile` **ignores the data-filter's `None` deny verdict on the link-unsupported fallback branch** (CVE-2026-87910) onto the May 6 extraction page — fallback branches are where filter verdicts get dropped](alerts/2026-09-22-dancer2-guard-semantics-header-name-crlf-hook-refusal-dispatch-and-path-spelling-differentials-ghsa.md)

- [**AD CS plaintext CA fetch → trust-store poisoning (Sept 21 fold, CVE-2026-12249)**: Canonical ADSys ≤0.16.2 auto-enrolls AD CS certificates via a vendored Samba GPO script that fetches the CA cert with `GetCACert` over **plaintext `http://`** — an **unauthenticated on-path attacker** returns an arbitrary root CA, which ADSys installs into the **OS trust store** via `update-ca-certificates` → every TLS client on the host accepts rogue certs for any domain, persistently. Axes: grep enrollment/GPO agent source for `http://` + CA-fetch/trust-update calls (trust material over unauthenticated channels = anchor injection), the CA hostname arrives via GPO so a DNS answer controls the leg, and the injected root survives reboots = persistence; fingerprint fleet versions, prove only with lab-generated fake roots + owned canaries. Folded onto the July 27 directory-boundaries page alongside the SSSD sudo/GPO cluster](alerts/2026-07-27-directory-cluster-agent-document-boundaries-ghsa.md#september-21-follow-up-adsys-ad-cs-ca-fetch-over-plaintext-http-poisons-the-system-trust-store)

- [**Management-plane config-write ladders + TOCTOU onboarding race + flat authz drift (Sept 21)**: nginx-ignition `/api/users/onboarding/finish` is **anonymous, all-ReadWrite, and TOCTOU-raced** → unauthenticated admin creation, multiple admins per concurrent burst (CVE-2026-61628) — sweep `/setup/*` `/init/*` route families and race them. **OpenStack Octavia critical pair**: an RFC-3986 validator **percent-encodes control chars before validating while storage keeps raw** → newline-injected HAProxy directives via L7 `redirect_url` (CVE-2026-94571), and `tls_ciphers` writes verbatim to the same generated config (CVE-2026-94572) — enumerate every field rendered into config files. **ZLMediaKit unauth `setServerConfig`** writes shell text into `ffmpeg.snap`, executed later by `getSnap` (CVE-2026-67827): config-set APIs are RCE with a delay. **x-ui**: signed cookie carries the full user object with **no DB revalidation** → rotated passwords don't revoke old admin sessions (CVE-2026-79317); low-role template edit + restart **rebinds the management gRPC off loopback** (CVE-2026-79316). **jshERP nine-GHSA ladder**: `type=UserRole` generic updater = **self-grant tenant admin in one POST** (94411), `resetPwd` any user (94412), `/user/info` leaks **unsalted MD5 hashes** (94413), key-iteration cross-tenant enum (94494). + fold: `pquerna/otp` **ships no consumed-TOTP tracking by design** → one captured code is a ~30 s reuse lane (CVE-2026-61630) onto the Sept 18 token page](alerts/2026-09-21-management-plane-config-writes-toctou-onboarding-race-and-flat-authz-drift-ghsa.md)

- [**Legacy-CMS internal-namespace injection + URL-ingest SSRF + media-panel RCE ladder (Sept 21)**: CuteNews `cn_parse_url()` **deserializes base64 `__post_data` and merges it into `__`-prefixed internal request variables** — caller keys collide with app state; injected `__referer` renders as a `javascript:` link on `msg_info`, closing the blind-state-write → session-XSS loop (CVE-2026-36471/36472); Media Manager **Upload-by-URL = standalone SSRF leg** validators never cover (CVE-2026-36469); media-panel unrestricted upload = login-to-RCE (CVE-2026-36467); fuzz parameter **names** and **Referer-on-POST** for reflection (CVE-2026-36468/36470). Rule: sweep name-blind internal-namespace merges (`extract()`, `parse_str` no-target, `__`-prefix states), prove injection→read-sink chains, and URL-ingest features are SSRF even when input validators pass. + folds: Concrete CMS 8-GHSA cluster (**DNS-pin reused cross-port → rebinding import SSRF with saved-file response oracle**; anonymous-minted selector token + empty query = full account enumeration; CSRF token bound to user+action not object; source-side-only authz on relationship writes), Jenkins Script Security `@Builder` **class-name annotation member the whitelist never parses** → Pipeline sandbox escape (CVE-2026-92126, 8.5), Netty **semicolon-gated chunk validator lets `0\rX` through** + split-TE + trailing-control-byte RTSP method trim defeating the patched HTTP sibling (CVE-2026-93566/93565), Quarkus **security-matcher vs dispatcher normalization split** (CVE-2026-87743)](alerts/2026-09-21-cutenews-internal-namespace-injection-url-upload-ssrf-and-media-rce-ladder-ghsa.md)

- [**Auth-method precedence + verb-allowlist bypass + ACL tie-break drift (Sept 21)**: Airflow request with **cookie AND bearer** executes + audit-logs as the **cookie's** principal — send two principals at once, diff executing-vs-logged identity (CVE-2026-82355); logout revokes **only the `_token` cookie**, bearer tokens survive for full TTL — replay-after-logout on every credential transport (CVE-2026-86473); count-query missing the row filter → `total_entries` hidden-Dag oracle (CVE-2026-75158). MISP octet: login security controls gated on **POST/PUT only** → any other verb skips bruteforce-block + OTP 2FA + logging (CVE-2026-94379); read-only API key restores full account perms in one call (CVE-2026-94381); `save()` without unsetting client `id` where **sibling loops unset it** → cross-event report reparent (CVE-2026-94374); non-XML-content XML import SSRF + galaxy-name sprintf XSS. + Dogtag **lexicographic ACL tie-break** (wildcard beats specific literal, CVE-2026-80110), Hatchet **empty-`state` sentinel accepted** → login-CSRF (CVE-2026-61687), MINA fix landed on **one branch only** — "fixed" versions still vulnerable (CVE-2026-94301, 9.8) (16 GHSAs)](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md)

- [**Automation-platform credential-test exfil + FQDN-endpoint metadata SSRF (Sept 21)**: AAP Controller Vault plugin `kubernetes_auth()` sends the **controller pod's own SA token** to the URL inside a credential definition when that credential is *Tested* → credential-create role exfiltrates a token with control-plane pod CRUD + secret read (9.6, CVE-2026-12564): every "verify this credential" button that connects out with the platform's identity is an exfil channel. OpenShift Router accepts **FQDN-type EndpointSlice endpoints** → Service proxies to a hostname resolving to cloud metadata, bypassing the prior IP denylist (CVE-2026-42965): IP-parsing validators cannot check names — grep for `net.ParseIP`. Quay `GLOBAL_READONLY_SUPER_USERS` can read **robot tokens for foreign repos** → impersonate any robot (CVE-2026-18255): read-only global roles forget the credential-view sub-resources. + folds: sequoia-openpgp **absent Key Flags subpacket → inferred capabilities → back-signature bypass → signature forge** (CVE-2026-42784) onto the Bouncy Castle crypto-boundary page; RHOAI training-operator **aggregation onto stock `edit`/`admin` roles + PodTemplateSpec passthrough** (CVE-2026-18982/18951), DSPO **weak-PRNG-derived MariaDB/MinIO credentials** (CVE-2026-18611), and DSPO over-scoped ClusterRole post-compromise ladder (CVE-2026-18608) onto the Aug 10 AI control-plane page](alerts/2026-09-21-automation-platform-credential-test-exfil-and-fqdn-endpoint-metadata-ssrf-ghsa.md)

- [**Workflow-platform internal deputies + presigned-URL operation confusion (Sept 21)**: Temporal completion callbacks decide **internal vs external from a caller-supplied `source` header** — non-empty flag makes History re-target the request at the **internal frontend client** (authorizes everything as system admin, no auth), rewriting only scheme+host so your path/query/body ride along → cross-namespace namespace-delete/register/configure; precondition = `internal-frontend.rpc.httpPort` non-zero + `callbacks.allowedAddresses` non-empty (CVE-2026-87858). Temporal's registered **`subprocess` compute provider takes program+argv from the caller's request** and the enable-allowlist check is **skipped when unset (the default)** → namespace-write role → immediate RCE as the server account holding every-namespace persistence creds + cluster TLS (CVE-2026-89139, 1.31.0–1.31.2). NooBaa SigV4 **drops unsigned `x-amz-` headers from the signature calc instead of rejecting** → add `x-amz-copy-source` to a presigned PUT and it becomes server-side CopyObject of anything the signer can read (CVE-2026-94368). Axes: **caller-supplied headers that select internal trust context, default-unset allowlists enforce nothing, presigned URL scope ≠ granted operation**. + CRI-O checkpoint security-state retention fold (CVE-2026-92574)](alerts/2026-09-21-temporal-internal-deputy-subprocess-provider-and-noobaa-presigned-copyobject-ghsa.md)

- [**SAML assertion attack-surface testing (Sept 21 methodology)**: the ToB "SAML is a fractal of bad design" retirement essay inverted into a target-surface map — six layers (XML/DTD, C14N, enveloped signature, conditions, binding parity, identity linking) each an independent parser awaiting a differential; mutation battery order (metadata fingerprint → own-signed canary → XSW family → comment/whitespace c14n family → condition-stripping matrix → per-binding verdict table → Go round-trip asymmetries → two-tenant linking review); the shape-normalization defense inverted as a bypass target (mutate only inside the grammar the normalizer tolerates); report which copy of the document the signature check vs the identity check read](methodology/saml-assertion-attack-surface-testing.md)

- [**REDCap survey-passthrough route confusion → unauth RCE (Sept 20)**: a valid **public survey hash** gates a passthrough router that can reach an **unintended controller route**, and the Data Import handler takes a crafted **file-path/stream parameter** → RCE with no login (CVE-2026-90817, REDCap 13.3.0+). Rule: **a public token authenticates a context, not the internal route family behind it** — sweep route/action selectors from any token-gated passthrough (surveys, share links, form tokens), treat import handlers' path/stream params as file sinks, and check hash enumerability as the precondition-collapse axis](alerts/2026-09-20-redcap-survey-passthrough-route-confusion-unauth-rce-ghsa.md)

- [**Media-pipeline edge surfaces (Sept 20)**: getID3 **shells out with the filename unescaped** → a media file *named* with shell metacharacters runs commands in any embedding PHP app (8.8, CVE-2026-94106) — fuzz filenames, not just contents; getID3 **XXE via XML metadata embedded in a media container** → file read/SSRF with no XML endpoint (CVE-2026-94108); openEQUELLA **FreeMarker SSTI → RCE** through unsandboxed template resolver on author-facing summaries/portlets/MIME templates (8.8, CVE-2026-94109); NivoCart **chunked-upload branch skips the extension validation** the single-file branch runs (`chunks ≥ 2`) → view-only user PHP upload RCE (8.8, CVE-2026-94104). Rule: the upload endpoint's own checks passing is not a negative control — filename sinks, sidecar parsers, template-backed fields, and chunk branches are four extra paths (4 promoted GHSAs + 6 folds)](alerts/2026-09-20-media-pipeline-edge-surfaces-filename-shellout-metadata-xxe-author-template-rce-ghsa.md)


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
