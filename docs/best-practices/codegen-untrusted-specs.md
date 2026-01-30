# Code generation: treat specs as untrusted input

Security tooling and developer pipelines often **generate code** from inputs like:

- OpenAPI / Swagger specs
- GraphQL schemas
- protobuf/IDL definitions
- “enum descriptions”, docstrings, markdown, and comment blocks

If you ingest these artifacts from untrusted sources (or if they can be modified by attackers), you can end up with **code injection into generated output**.

A recent example:

- **Orval** code injection via unsanitized `x-enumDescriptions` when rendered into JavaScript comments (CVE-2026-25141 / GHSA-gch2-phqh-fg9q).

## Threat model

Attackers target:

- CI jobs that run codegen automatically on PRs
- internal developer tooling that fetches specs remotely
- monorepos where one package’s spec generation affects another package’s build

Impact ranges from:

- malicious code committed into the repo
- arbitrary code executed during generation/build steps
- supply-chain compromise of published artifacts

## Defensive guidance

### 1) Upgrade quickly for generator vulnerabilities

When a generator tool ships a security fix:

- bump to the patched version in all workspaces
- invalidate caches
- re-run codegen in a clean environment

### 2) Run codegen in a sandboxed, least-privileged environment

- Use dedicated CI identities with minimal permissions.
- Avoid long-lived credentials in codegen jobs.
- Prevent network egress when possible.
- Treat generated output as *build artifacts*, not trusted source, unless reviewed.

### 3) Validate and sanitize “documentation fields”

If you maintain a generator:

- never embed untrusted strings into executable contexts (code, templates, comments) without strict escaping
- treat comment delimiters as dangerous (`*/`, `<!--`, etc.)
- consider rendering untrusted strings as data (e.g., JSON string literals) rather than comments

If you consume a generator:

- assume spec metadata fields can be hostile
- avoid enabling “preserve comments from spec” features for untrusted inputs

### 4) CI hardening for PR-driven codegen

- Do not run privileged codegen on untrusted PRs.
- If codegen must run, do it in a restricted environment and require review before merging generated diffs.
- Consider:
  - running codegen only after merge
  - a “bot PR” workflow that regenerates code from trusted main

## References

- GitHub Advisory: https://github.com/advisories/GHSA-gch2-phqh-fg9q
