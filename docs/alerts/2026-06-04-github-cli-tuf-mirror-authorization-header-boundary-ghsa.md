# GitHub CLI TUF mirror authorization-header boundary

## Operator value

GitHub Advisory Database published [GHSA-8xvp-7hj6-mcj9 / CVE-2026-48501](https://github.com/advisories/GHSA-8xvp-7hj6-mcj9) for GitHub CLI on 2026-05-29 and updated it on 2026-06-04. The durable lesson for authorized supply-chain and developer-workstation assessments is not just "upgrade `gh`". It is a repeatable trust-boundary check:

> A CLI that uses one shared authenticated HTTP client for API calls and artifact-verification fetches can leak bearer credentials to non-API hosts when host attribution, wildcard subdomain handling, or enterprise-token fallback logic is wrong.

Use this page to test whether release-verification, attestation, provenance, or TUF-client workflows send tokens only to the intended API origin.

## Affected surface

- Advisory: [GHSA-8xvp-7hj6-mcj9 / CVE-2026-48501](https://github.com/advisories/GHSA-8xvp-7hj6-mcj9)
- Product: `github.com/cli/cli/v2` / GitHub CLI
- Affected versions: `<= 2.92.0`
- Fixed version: `2.93.0`
- Commands called out by the advisory:
  - `gh attestation`
  - `gh release verify`
  - `gh release verify-asset`
- Boundary:
  - `github.com` tokens must not be attached to non-API `*.github.com` hosts such as `tuf-repo.github.com`.
  - `GH_ENTERPRISE_TOKEN` / `GITHUB_ENTERPRISE_TOKEN` must not be attached to unrelated external TUF or artifact hosts such as `tuf-repo-cdn.sigstore.dev` or Azure Blob Storage.

## Recon workflow

1. Confirm assessment scope covers developer workstations, CI images, release automation, or supply-chain verification tooling. Do not inspect real token values unless the owner explicitly authorizes secret-handling.
2. Inventory `gh` installations from controlled hosts or owner-provided manifests:

   ```bash
   gh --version
   command -v gh
   gh auth status --hostname github.com
   env | grep -E '^(GH_TOKEN|GITHUB_TOKEN|GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN)='
   ```

   Redact token values in notes and reports.
3. Identify workflows that call release or attestation verification:

   ```bash
   grep -R "gh attestation\|gh release verify\|gh release verify-asset" .github scripts Makefile package.json 2>/dev/null
   ```

4. Prioritize cases where:
   - `gh <= 2.92.0` is present;
   - `gh` is authenticated during verification commands;
   - enterprise-token environment variables are set in CI or release runners;
   - outbound traffic can reach TUF mirrors, Sigstore CDN, or artifact-storage hosts through a proxy that can log destination metadata.

## Safe validation pattern

Use a canary token with minimal permissions and a disposable test repository. The goal is to prove header misrouting, not to harvest real credentials.

1. Create or request a test environment with:
   - vulnerable `gh` version (`<= 2.92.0`);
   - a canary `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, or `GITHUB_ENTERPRISE_TOKEN` value that has no access to sensitive repositories;
   - a logging HTTPS proxy or lab DNS/TLS interception point approved by the owner.
2. Run one affected command against a harmless public release or test artifact:

   ```bash
   HTTPS_PROXY=http://127.0.0.1:8080 \
   GH_TOKEN=ghp_CANARY_REDACTED \
   gh release verify --repo OWNER/REPO TAG
   ```

   Adjust the command to the target workflow; do not publish real owner/repo names if they are sensitive.
3. Inspect outbound requests by destination host and request headers. Evidence is sufficient if the proxy shows an `Authorization` header attached to a non-API host involved in TUF or artifact retrieval.
4. Repeat with `gh 2.93.0` or later to show the boundary is contained: verification fetches should proceed without attaching GitHub bearer tokens to non-API hosts.

## What to capture

- `gh --version` output and installation source.
- The exact verification command class used (`attestation`, `release verify`, or `release verify-asset`).
- Environment-variable names present, with values redacted.
- Destination host, path class, and whether an `Authorization` header was present. Redact the header value; a prefix plus length is enough.
- Before/after behavior across vulnerable and fixed versions when available.

## Report framing

Frame this as credential-boundary confusion in client-side supply-chain tooling:

- The CLI should bind authentication headers to the exact API origin that requires them.
- Artifact-verification fetches should run as unauthenticated or with host-specific credentials only.
- Wildcard subdomain normalization must not collapse every `*.github.com` host into the `github.com` API trust zone.
- Enterprise-token fallback must fail closed when a request target is not a configured enterprise host.

A strong finding demonstrates token-bearing requests crossing to an unintended host with a canary credential. Avoid reporting only "old `gh` found" unless the affected commands and authenticated execution path are reachable in the assessed workflow.

## Sources

- GitHub Advisory Database: [GHSA-8xvp-7hj6-mcj9 / CVE-2026-48501](https://github.com/advisories/GHSA-8xvp-7hj6-mcj9)
- GitHub CLI release: [`v2.93.0`](https://github.com/cli/cli/releases/tag/v2.93.0)

## October 15 follow-up: three more `gh` trust-boundary bugs in one hour — regex signer matcher, unescaped URL path segments, and a masking logic inversion (3 GHSAs, all fixed in 2.97.0)

GitHub published three more GitHub CLI advisories at 18:0xZ on 2026-10-15, all fixed in [`v2.97.0`](https://github.com/cli/cli/releases/tag/v2.97.0). Each one is a reusable boundary check for supply-chain and developer-workstation assessments.

### 1. Attestation verification bypass — `--signer-repo` / `--signer-workflow` are regexes, not literals ([GHSA-mm27-mwq9-fr5g](https://github.com/advisories/GHSA-mm27-mwq9-fr5g) / CVE-2026-64655)

`gh attestation verify` builds a certificate-SAN matcher by interpolating the `--signer-repo` / `--signer-workflow` flag values into a **regular expression without escaping metacharacters**. GitHub permits `.` in organization, repository, and workflow-path names, and unescaped `.` is the any-single-character wildcard — so an attacker-controlled repository named `github/artifact.attestations-workflows` satisfies a verification pinned to the trusted signer `github/artifact-attestations-workflows`. Attested artifacts from the lookalike repo pass the signer check. The advisory explicitly notes `--repo` / `--owner` were *not* affected because those flags use exact string comparison.

- **Durable rule: any "trusted name" allowlist built by string-interpolating user input into a matcher language silently upgrades separators to wildcards.** Audit every verification gate (Sigstore/cosign `--certificate-identity*`, policy engines, CI trusted-signer lists, log-viewer filters — compare this page's sibling fail2ban `on <ip>` and GitLab regex-validator RCE legs from the Oct 13 wave) for literal-vs-regex semantics, then probe with metacharacter lookalikes that the *name-issuing system permits*. The name grammar of the issuing platform is part of your payload surface: check what characters names may contain before trusting name-equality gates downstream.
- **Sibling-flag parity is the fast oracle here:** the exact-comparison `--repo`/`--owner` path vs the regex `--signer-*` path is the same "fixed one call site, missed the sibling" genealogy as everything else on this page family. When auditing a verification CLI, grep how each identity-shaped flag is compiled and diff comparison semantics flag-to-flag.
- **Authorized-engagement angle:** where CI pins `gh attestation verify --signer-repo OWNER/REPO` (or `cosign verify --certificate-identity-regexp`), the pinned name is only as strong as its escaping. Fingerprint the pinned name's metacharacters (`.` `-` `_`), check whether a lookalike name is registrable on the host platform, and note that verification *bypass* is a supply-chain finding even when the artifact itself is inert. Lab proof only: own both the trusted-name template and a lookalike repo under your org, sign an inert artifact, and record that the pinned matcher admits it on `gh < 2.97.0`.

### 2. Client-side path traversal — request URLs built from unescaped variable path components ([GHSA-4fjg-2h4q-fwg3](https://github.com/advisories/GHSA-4fjg-2h4q-fwg3) / CVE-2026-64653)

Some `gh` request URLs — REST calls in particular — interpolated variable components into the request path **without percent-encoding**, so a value containing URL path metacharacters breaks out of its intended segment and makes `gh` address a different API endpoint than the user intended (read or act on the wrong resource).

- **Durable rule: server-side path traversal has a client-side twin that gets far less attention.** When any value derived from an untrusted repository, release, issue, or workflow name flows into a request-path segment of an API client, that client becomes a confused deputy: `run gh against repo X` can be steered by repo-X-owned names to call endpoints the operator never intended. Hunt pattern in any API-client codebase: grep URL construction sites for string formatting (`fmt.Sprintf`, template strings, `url.Parse` of hand-built paths) and check that each variable component is escaped per-segment.
- **Authorized validation:** with owner consent, run the affected CLI version against a disposable repo whose resource names carry path metacharacters (`%2f`, `../`, extra `/`) and observe which API endpoint actually receives the request via an approved logging proxy. Stop at destination-mismatch evidence — do not act on other tenants' resources.

### 3. `gh auth status` masks after the last underscore — partial token disclosure ([GHSA-cg6r-mpgc-h9mm](https://github.com/advisories/GHSA-cg6r-mpgc-h9mm) / CVE-2026-64652)

The masking logic redacted **only the characters after the last underscore** instead of everything after the known prefix. Token formats whose body contains underscores — fine-grained PATs (`github_pat_*`), App installation/user tokens (`ghs_*`, `ghu_*`, e.g. `ghs_<APPID>_<JWT>`), and the Actions `GITHUB_TOKEN` — printed most of the secret in a command users believe is a safe diagnostic. Classic PATs (`ghp_*`) were unaffected because their body has no underscore.

- **Durable rule: suffix-anchored masking (`keep-before-last-delimiter`) inverts under token-format evolution.** Any redaction routine keyed on "last separator" is a latent leak the day a new credential format introduces that separator mid-secret. Grep masking/redaction helpers in CLIs, log filters, and CI output scrubbers for `lastIndexOf`/`rfind`-style anchoring and verify they mask by *known prefix*, not delimiter position.
- **Assessment application:** during CI/CD log review with scope permission, grep build logs, bug-report attachments, and terminal captures for the leak shape (`github_pat_` prefix with a visible long tail) — partial-token material in logs is a reportable credential-exposure finding, and combining the visible tail with the attacker-known prefix format shrinks the search space for the remainder. Report with values redacted; a prefix plus redacted-length plus occurrence location is sufficient evidence.

**Batch lesson:** one product, one release band, three distinct boundary classes (matcher-language escaping, URL-segment escaping, masking anchoring) — the version-pin check (`gh --version` vs 2.97.0) is the recon trigger, and the three checks above generalize to any CLI or CI plugin that verifies, requests, or displays credentials.
