# Yeoman generator bootstrap package-install boundary (GHSA-vv9j-gjw2-j8wp, 2026-05-26)

**Signal:** GitHub published `GHSA-vv9j-gjw2-j8wp` / `CVE-2026-42089` for `yeoman-environment`. Versions `>= 2.9.0, < 6.0.1` call `installLocalGenerators()` on caller-supplied generator package names and install missing local packages without asking the user first. In downstream CLIs that derive generator names from project configuration, templates, scaffolding manifests, or repository-controlled input, this becomes **project-file influenced npm package installation during CLI bootstrap**.

The durable operator value is the chain shape: **trusted scaffolding CLI + attacker-controlled generator/package name + implicit install = package install-hook code execution**. Treat this as a reusable supply-chain and developer-workstation boundary test for authorized assessments, not just a Yeoman version check.

## Why it matters for authorized testing

This is useful when an assessment includes internal developer portals, repo bootstrap commands, project generators, cookiecutter-style scaffolding, monorepo onboarding scripts, or AI/agent workflows that run project setup commands automatically.

Reusable lessons:

1. **Generator resolution is package resolution.** If a CLI converts a project-controlled name into `generator-*` or another npm package spec, the lookup can cross from local project logic into registry trust.
2. **Missing dependency recovery can become execution.** Installing npm packages is not passive; lifecycle hooks and transitive tooling can run during or after install depending on the package manager and caller options.
3. **Promptless bootstrap is a trust-boundary failure.** The patch adds an explicit confirmation before local packages are installed, with a force path only when the caller intentionally opts in.
4. **Downstream wrappers define exploitability.** The core library vulnerability needs a consumer that passes attacker-influenced config into generator execution. Your finding should prove that data path before claiming end-to-end code execution.

## Validation workflow

Only validate against repositories, CLIs, and package namespaces that you own or are explicitly authorized to test. Do not publish or typosquat real package names to prove the issue.

### Recon

1. Identify apps or internal tools that depend on `yeoman-environment` `>= 2.9.0, < 6.0.1`:
   - `npm ls yeoman-environment`
   - `npm explain yeoman-environment`
   - dependency lockfile search for `"yeoman-environment"` and affected versions.
2. Find bootstrap paths that call Yeoman execution based on project files, template metadata, command-line parameters, or remote repository content.
3. Trace whether missing generator names are passed into `installLocalGenerators()` or equivalent auto-install behavior.
4. Note execution context: developer laptop, CI worker, Codespaces/devcontainer, internal portal runner, agent sandbox, or build farm.

### Safe proof shape

Prefer a private registry or local file/tarball package controlled by the customer.

1. Create a benign marker package under a test namespace, for example `@customer-test/generator-marker`, whose lifecycle script writes a harmless marker file or prints a unique string.
2. Configure the vulnerable downstream CLI or fixture project to request that missing generator package through the same project-controlled path an attacker could influence.
3. Run the bootstrap command in an isolated working directory with disposable npm cache and no production credentials.
4. Confirm whether the package installs without an explicit confirmation prompt and whether the marker executes or the package lands in the local repository.
5. Repeat with `yeoman-environment` `6.0.1` or a patched downstream wrapper and show that installation is blocked by default unless the user approves or a deliberate force flag is used.

Evidence to capture:

- affected package and version range;
- exact downstream CLI, command, and project-controlled field;
- package spec that was derived from attacker-controlled input;
- whether a prompt appeared;
- install destination and package-manager logs;
- marker output/file from the benign package;
- isolation controls used to avoid touching production credentials or public package names.

## Variant checks

- Generator names sourced from `package.json`, `.yo-rc.json`, template manifests, repo metadata, URL parameters, or AI-generated project files.
- Package-name transforms such as adding `generator-`, scope stripping, version/range suffixes, registry aliases, git URLs, tarball URLs, or local `file:` specs.
- Non-interactive CI/agent contexts where prompts are auto-accepted, disabled, or bypassed by wrapper flags.
- Private registry fallback, npm config inheritance, and workspace-local `.npmrc` registry overrides.
- Lifecycle script behavior under the package manager actually used by the target (`npm`, `pnpm`, `yarn`) and its configured script restrictions.
- Previously installed malicious generator packages that make later runs appear safe because no new install is needed.

## Reporting heuristic

Frame the finding as **attacker-influenced generator bootstrap to implicit package installation**. A strong report should include:

- the repository-controlled input that chooses the generator/package;
- the downstream command a developer or automation runner is expected to execute;
- the trust boundary crossed from project metadata into package installation;
- whether package lifecycle code execution was demonstrated with a benign marker;
- runner context and credential exposure assumptions;
- registry/package-name collision or typosquat risk, if applicable;
- patched behavior in `yeoman-environment` `6.0.1`, especially the confirmation gate added before `repository.install()`.

## Non-signal this hour

Other checked sources did not add a fresh promotable item beyond already-covered material: CISA KEV stayed on catalog `2026.05.26` with the already-promoted LiteSpeed cPanel plugin privilege-escalation entry; PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed did not surface a new durable offensive-operator delta. `GHSA-f659-372h-6x3x` for Netty OHTTP HPKE failure handling was reviewed but not promoted because the advisory does not yet provide a replayable operator validation path beyond crypto/implementation review.

## Sources

- [GitHub Advisory Database: `yeoman-environment` arbitrary package installation (`GHSA-vv9j-gjw2-j8wp`)](https://github.com/advisories/GHSA-vv9j-gjw2-j8wp)
- [Yeoman advisory: arbitrary package installation without user confirmation](https://github.com/yeoman/environment/security/advisories/GHSA-vv9j-gjw2-j8wp)
- [Patch commit `78d2af7`: ask before installing local packages](https://github.com/yeoman/environment/commit/78d2af7e60294784b8a8b3b3b5099c6874b6a1fa)
- [Patch PR `#753`: ask before installing local packages](https://github.com/yeoman/environment/pull/753)
