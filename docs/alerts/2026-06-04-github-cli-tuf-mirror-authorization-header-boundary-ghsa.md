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
