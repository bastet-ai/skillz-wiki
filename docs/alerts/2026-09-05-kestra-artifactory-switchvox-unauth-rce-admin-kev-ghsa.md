# Unauthenticated RCE / admin-escalation KEV wave

**Why this is worth an operator page.** CISA KEV added three actively-exploited, *unauthenticated* entries on 2026-09-02/04, all with forensic-triage flags (`Yes`) and 2026-09-05 due dates. Each is a durable, replayable operator boundary, a suffix-match auth bypass to RCE, a default-config auth bypass to admin, and a single-request SQLi→RCE, and each maps to a class of control that shows up across many products:

- **CVE-2026-49869**, Kestra OSS (event-driven orchestration), CWE-78 + CWE-287. `AuthenticationFilter` whitelists the public config endpoint with `request.getPath().endsWith("/configs")`, a *suffix* match, not an exact path. Any API path whose last segment is `configs` skips Basic Auth entirely. Combined with Kestra shipping script-execution plugins (`plugin-script-shell`, `plugin-script-python`, …) enabled by default, an unauthenticated remote attacker can create and execute arbitrary workflows → unauthenticated RCE as root in the worker container. Fixed in 1.0.45 / 1.3.21.
- **CVE-2026-82329**, JFrog Artifactory, CWE-287. Under **default configuration**, an unauthenticated attacker with network access can obtain administrative privileges.
- **CVE-2026-9586**, Sangoma Switchvox SMB Edition 8.3 (104997), CWE-89, CVSSv4 9.3. The unauthenticated `/pa` endpoint parses `<PolycomIPPhone>` XML, and the `PhoneIP` field is concatenated into a PostgreSQL query with **no sanitization or parameterization**. A single crafted request executes arbitrary SQL as the PostgreSQL superuser → RCE. Patched in 8.4.0.2 (July 14 2026). Public research documents in-the-wild attempts.

This page gives the durable operator workflow: exposure recon, boundary validation, and compromise-verification checks for each. Chromium V8 type-confusion (CVE-2026-85046, added the same day) is a browser memory-safety entry with no public exploit path; it is tracked but **not** turned into an operator page.

## Kestra, suffix-match auth bypass → unauth workflow RCE (CVE-2026-49869)

The control that broke is an **exact-path vs suffix-match** decision in an auth filter:

```
AuthenticationFilter: request.getPath().endsWith("/configs")   // intended: only /api/v1/configs is public
```

Because it is `endsWith`, any route ending in `configs` (e.g. a workflow/execution route whose final segment is `configs`) passes without Basic Auth. Once auth is skipped on an execution-capable route, the attacker author + run a workflow. With `plugin-script-shell`/`plugin-script-python` enabled by default, the workflow body is an OS command / Python payload.

Operator boundary checks (authorized scope / lab only):
- **Auth-filter differential:** for each candidate public/execution route, compare `GET /…/configs` (public) vs a same-shape route that should require auth. The exploitable signature is *no 401 on a route whose last segment is `configs` but that is not the config endpoint*.
- **Default-plugin inventory:** confirm which script-execution plugins are loaded (`plugin-script-shell`, `plugin-script-python`, etc.). Default-enabled shell/python plugins turn any workflow-creation primitive into RCE.
- **Version scoping:** 1.0.45 / 1.3.21 are the first fixed; record the exact build to know whether the bypass is present.

Do not author or execute a real workflow on a production instance; prove the boundary with the auth-filter differential (auth required vs not) on a lab Kestra, and stop at "unauth reach + execution-capable route reachable" rather than spawning processes.

## JFrog Artifactory, default-config unauth admin (CVE-2026-82329)

Improper authentication that, **out of the box**, lets an unauthenticated network attacker reach administrative functions. Durable operator lesson: Artifactory is a high-value artifact/replication hub and a frequent pivot point in CI/CD and supply-chain chains, so "default config" is itself the vuln.

Operator boundary checks (authorized scope / lab only):
- **Admin-route probing without auth:** on a scope-authorized Artifactory, enumerate the admin/security UI and API paths and record which respond without credentials on the default-config build. A positive (admin surface reachable unauth) is the finding; record route + HTTP status, not admin data.
- **Default-config state:** capture the effective auth setup (is a realm / admin bootstrap configured, or is it still on the installer default?) so "default" can be distinguished from "misconfigured."
- **Supply-chain relevance:** note that unauth admin on a package repository implies read of any artifact and the ability to push tampered ones; flag as a supply-chain blast radius without actually pulling or publishing artifacts.

Do not read, download, or publish artifacts, and do not create admin accounts on a production system. Boundary confirmation (unauth admin route reachable on default config) is the report.

## Sangoma Switchvox, unauth SQLi → RCE via `/pa` PhoneIP (CVE-2026-9586)

Public research (SRA Labs + Horizon3) documents the full chain and **in-the-wild** exploitation:

1. Unauthenticated `POST /pa` with a `POSTDATA` body that **starts with `<PolycomIPPhone>`**.
2. The handler (`PhoneAppsHandler.pm`) validates only the `<PolycomIPPhone>` prefix, no content sanitization, stores it, and dispatches a `tel_notify` command.
3. `tel_notify()` parses the XML (`XML::Simple::XMLin`) and extracts `PhoneIP` with **no validation**.
4. `PhoneIP` is concatenated (single-quoted context) into a PostgreSQL query and executed via `$db->query("sql", $sql)` **as the PostgreSQL superuser**.

Documented payload shape (for lab reproduction only, not for production):

```
POST /pa  (POSTDATA, body begins with <PolycomIPPhone>)
… SELECT proposed_extension FROM auto_phone_config WHERE ip_address = '<PHONEIP>'; COPY (SELECT "") TO PROGRAM '<CMD>'; …
```

i.e. a SQLi escape out of the single-quoted `ip_address` value into a `COPY … TO PROGRAM` command execution as the DB superuser. Patched in Switchvox 8.4.0.2.

Operator boundary checks (authorized scope / lab only):
- **Endpoint existence + version:** identify Switchvox SMB and the build; 8.3 (104997) is in scope, 8.4.0.2+ is patched. Record the exact version from the portal/headers.
- **Auth gate on `/pa`:** confirm `/pa` is unauthenticated and accepts a `<PolycomIPPhone>`-prefixed body (the prefix check is the only gate). A body that is accepted and parsed past the prefix is the boundary evidence, stop before SQL injection.
- **Sink characterization:** note the single-quoted `ip_address` SQL context + `COPY … TO PROGRAM` capability (superuser DB). Prove on a lab Switchvox with a marker command (e.g. write a canary file) at most; never run a reverse shell or read the production DB.
- **Compromise verification (owner-directed):** if SSH access exists, Horizon3 notes exploit payloads can be observed in `/var/log/switchvox/db-quirks.log`. A read-only grep for `db-quirks.log` entries with `COPY … TO PROGRAM` / shell command strings is the owner-directed hunt; absence of IOCs is not proof of non-compromise.

## Durable operator value

1. **Suffix-match vs exact-path auth filters are a reusable bypass axis.** Any auth/whitelist check that uses `endsWith`, `contains`, or a non-anchored path match can be satisfied by a *different* route with the same suffix. Audit every "public endpoint" allowlist for exactness; the exploit is "a route that should require auth ends in the same string as one that shouldn't."
2. **Default-enabled execution plugins convert workflow/config writes into RCE.** For orchestration and automation products, inventory which script/code plugins are on by default. An unauth or low-priv write to a workflow/config is RCE the moment a shell/python plugin is present.
3. **"Default configuration" is itself a vulnerability class.** Artifactory's unauth-admin is a *default* state. For high-value hubs (package repos, artifact registries, orchestration servers), the recon question is "is this still on factory defaults?", and a yes is the finding.
4. **`COPY … TO PROGRAM` is the PostgreSQL RCE primitive** for unparameterized SQLi in a superuser-context DB. When a product embeds a PostgreSQL DB and injects user data into a query it runs as superuser, the endgame is `COPY TO PROGRAM`/command execution, recon for the sink, not just the injection.
5. **Obfuscated vendor handlers are still reverse-engineerable.** Switchvox ships partially-obfuscated Perl; public research recovered the exact sink via de-obfuscation. Obfuscation is not a control, it delays the sink identification.

## Safety

- **Authorized scope / lab only.** All three are unauthenticated and destructive-capable; any write to a production instance is an incident. Confirm the owner's approval level (recon vs. boundary proof vs. exploit validation) before each action.
- **No payload execution in scope** unless explicitly approved: no workflow execution, no admin account creation, no `COPY … TO PROGRAM`, no reverse shell, no artifact read/publish.
- **Compromise checks are read-only** and owner-directed (log review on owner-approved systems); preserve evidence rather than modifying it.
- Keep all credentials and session material out of the wiki and out of reports.

---

*Sources: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [NVD CVE-2026-49869](https://nvd.nist.gov/vuln/detail/CVE-2026-49869) · [Kestra GHSA-5vc5-wxxq-3fjx](https://github.com/kestra-io/kestra/security/advisories/GHSA-5vc5-wxxq-3fjx) · [NVD CVE-2026-82329](https://nvd.nist.gov/vuln/detail/CVE-2026-82329) · [JFrog security advisories](https://docs.jfrog.com/releases/docs/jfrog-security-advisories) · [NVD CVE-2026-9586](https://nvd.nist.gov/vuln/detail/CVE-2026-9586) · [SRA Labs Switchvox](https://labs.sra.io/posts/switchvox/) · [Horizon3 CVE-2026-9586 disclosure](https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/) · [Sangoma Switchvox 8.4.0.2 release notes](https://sangomakb.atlassian.net/wiki/spaces/Switchvox/pages/1802371073/Switchvox+-+Release+Notes+Version+8.4.0.2+July+14+2026)*
