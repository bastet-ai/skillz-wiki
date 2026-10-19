---
title: Package repository and proxy integrity testing
---

# Package repository and proxy integrity testing

Use this workflow during authorized assessments of CI/CD pipelines, developer workstations, internal package mirrors, and supply-chain bug-bounty programs (registries, proxies, lockfile tooling). It turns the Trail of Bits October 14, 2026 study *"Package managers have an integrity problem"* (25 package managers tested against a simulated malicious repository) into a reusable operator checklist. Source: [Trail of Bits, 2026-10-14](https://blog.trailofbits.com/2026/10/14/package-managers-have-an-integrity-problem/).

## Why this matters offensively

The post's threat model is the one red-teamers actually exploit: **a network position, a compromised registry/proxy/mirror, or a rogue internal mirror injecting code into legitimate packages.** Fewer than half of the 25 tested package managers verified downloaded contents against the lockfile by default, and only two verified the integrity of every package they downloaded. If you control (or can intercept) the delivery leg, most ecosystems hand you their build artifacts unverified.

Durable targeting facts from the study:

- **Verifies contents by default:** Go (checksum database + hardcoded key), vcpkg (hashes shipped in the manager source).
- **Verifies only if a lockfile with hashes is present and honored:** Bun, Bundler, Cargo, npm, pnpm, Poetry, SwiftPM, uv, Yarn.
- **Needs lockfile + extra opt-in steps:** Conda, Gradle, Pip, NuGet, Pub.
- **No effective verification with default flow:** CocoaPods, Composer, Conan, cpanminus, Gem, Maven, PowerShellGet, PSResourceGet, R.
- **cpanminus uses plaintext HTTP to the Perl repository by default** — any on-path network attacker injects code with no TLS to break first. Known for years, unfixed because HTTPS-by-default is "a breaking change."

## The "hash exists but doesn't verify" catalog

These are the highest-value recon facts: the lockfile *looks* like an integrity control but the manager doesn't enforce it, so a target team believes they're protected and they are not.

| Ecosystem | Illusion | Reality (per the study) |
| --- | --- | --- |
| Pub (Dart/Flutter) | `pubspec.lock` carries SHA-256 | On mismatch Pub **warns and installs anyway**, then rewrites the lockfile; `--enforce-lockfile` is non-default. |
| pnpm `< 11.4` (May 2026) | lockfile hashes | On mismatch it **overwrote the lockfile** with the attacker's hash until 11.4 changed the default. |
| Conan (C/C++) | 128-bit "recipe revision" hash | MD5 used as an *identifier*, not a check — it is never recomputed after download, and platform package revisions aren't even in the lockfile. |
| CocoaPods | SHA-1 `SPEC CHECKSUMS` | The checksum covers the Podspec, not the code — a compromised Git host serves a malicious tree at the **same tag**. |
| Composer (PHP) | `composer.lock` commit `reference` | The GitHub zipball is **not validated against the commit** (`shasum` empty) — the host can serve any ZIP for a real commit hash. |
| Gradle / Gem | lockfiles exist | `gradle.lockfile` / `Gemfile.lock` ship **without content hashes**. |
| NuGet | signature validation exists | Default `signatureValidationMode` is `accept` — **invalidly signed packages install** until `require` + trusted signers are configured. |
| Ruby/Java signing | RubyGems/Maven PGP available | Not verified by default; requires `gem cert --add` / `pgpverify-maven-plugin` allowlists. |
| Pip / uv / Poetry | PEP 740 attestations exist | **No verification path implemented** for identity-based attestations. |

## Audit-the-auditor trap

When a target (or you) reach for an "audit" command to close the gap, check **where the audit tool gets its trust material**:

- `npm audit signatures` does real Sigstore-backed registry-key validation — but only when run, and never during `npm install`.
- **`pnpm audit signatures` fetches the registry public keys *from the registry being audited*** — an adversary who controls the repository simply adds their own key and signature and passes the check. Treat any verifier that pulls trust anchors from the untrusted channel as a null control; this generalizes to any internal "supply chain scanner" you find on a target: ask which channel the scanner's own trust material arrives over.
- Go's checksum database is strong (transparency log, key hardcoded in the toolchain) but concentrates trust in one signing key, and transparency only protects against *selective* targeting if someone watches the log.

## Engagement playbook (authorized scope)

1. **Fingerprint the target's package flows.** From dev workstations, CI images, and `Dockerfile`s: which managers, which lockfiles committed, which mirrors/proxies in `PATH`/config (internal Artifactory/Nexus/verdaccio, `GOPROXY`, `PIP_INDEX_URL`, `npm config get registry`, Maven `settings.xml`, cpanminus defaults).
2. **Classify against the tables above.** A committed `Gemfile.lock` or `gradle.lockfile` is reproducibility theater — there is no content hash to defend. `composer.lock`/`Podfile.lock` integrity depends on the honesty of GitHub/Bitbucket serving, not on the lockfile.
3. **Network-position test (lab or explicit scope only).** Reproduce the study harness shape: disposable Docker image + sample project + a mitmproxy leg that mutates repository responses/package bodies; success = the sample program executes injected inert canary code. This is a validated design for testing your *own* pipelines and for registry/proxy bug bounties (Sigstore, registry, and proxy programs).
4. **Prove the mismatch branch.** For Pub/pnpm-class managers, force a hash mismatch and show the client rewrites the lockfile instead of failing — one screenshot closes the finding.
5. **Flag the HTTP defaults.** cpanminus-class cleartext fetches turn any shared network into a code-injection position without breaking TLS at all.

## Bug-hunting heuristics

- For **registry/proxy/Sigstore programs**: the reportable classes are (a) verifiers that take keys from the untrusted channel, (b) selective-targeting windows a transparency log would have caught, (c) attestation surfaces that exist but have zero consuming verifiers (PEP 740 today).
- For **CI/CD assessments**: treat every unpinned or unverified dependency leg behind a mirror you can influence (or a mirror cert the runner trusts) as standing code-execution into the build; pair with the wiki's CI/CD-to-cloud pivot chain once you have runner code execution.
- For **library-vs-application nuance**: many ecosystems tell *libraries* not to commit lockfiles — so a vulnerable library's downstream consumers have **no hash to check against**, silently widening any repository-side attack to every user.

!!! warning "Containment"
    Malicious-repository simulation belongs in disposable containers against mirrors you own or that are explicitly in scope. Never mutate public registry content, never intercept third-party developer traffic, and keep injected payloads inert (print-only canaries).

## October 19 07:1xZ follow-up: bootc — mutable OS image tags + policy fall-through = unsigned content becomes host root on reboot (66j5/CVE-2026-16487 high, CVSS 8.1)

`bootc` (immutable/OStree-style Linux boot from container images) with the **default** `containers-policy.json`: registries that fall through to the `default` scope of `insecureAcceptAnything` accept *any* content for a **mutable tag** (`:latest` and friends) during automatic or manual `bootc upgrade`. An attacker who can push to (or poison the mirror for) that tag gets arbitrary OS content applied **as the host root filesystem on next boot** — below every container runtime control, with A/B rollback making the swap look like a normal update.

This is the bootc-native twin of the Composer/CocoaPods "the tag is the trust anchor and the host serves it honestly" illusion in the catalog above — same defect shape one layer down the stack:

- **Signature policy is scoped per-registry; the default scope is the attack.** Audit any bootc/rpm-ostree-containing-host fleet by reading `/etc/containers/policy.json` (and drop-ins): `grep -A2 default` for `insecureAcceptAnything`, then enumerate which image references actually resolve via fall-through instead of a `signedBy`/`sigstoreSigned` rule. A `default: insecureAcceptAnything` plus any mutable tracked tag = standing supply-chain RCE below the OS.
- **Tag mutability is a separate audit axis from signature presence.** Even registries *with* signed rules are unsafe if the rule is `signedBy` without identity binding and the tag is mutable plus re-signable by a broad CI role; `bootc upgrade` re-resolves tags, so the delivery leg is revisited on every timer tick (`bootc-fetch-apply-updates.timer`). Recon: presence of that timer service on a host = the fetch leg fires unattended.
- **The write target is the root filesystem of a boot-managed host** — the report value is higher than package-manager code execution because persistence is the boot path itself; proof should stop at a pinned-digest mismatch observation in a lab VM, never a reboot into attacker content on shared systems.
- Bug-bounty angle: bootc-based distributions (Fedora CoreOS-class, image-mode RHEL, edge/IoT fleets) and their public registries qualify for the same "tag serves unverified content" report classes as this page's registry heuristics; the novel twist is the host-root blast radius.

## October 19 10:1xZ follow-up: bootc/ostree — staged deployments finalize without policy revalidation: hardening the policy does NOT evict already-staged unsigned content (72gj/CVE-2026-16460 high, CVSS 7.4)

The companion leaf to today's 66j5 entry above: in `bootc`/`ostree`, an image that was **already staged** (pulled under a prior permissive `insecureAcceptAnything` policy) is **finalized and booted without re-running the now-hardened signature policy**. Operators who respond to the fall-through finding by tightening `policy.json` get a false sense of closure — attacker content pulled *before* the fix stays bootable on reboot, full host compromise intact.

Durable rules:

- **Policy checks validate the fetch, not the boot.** Signature validation in bootc/ostree-class systems is a *pull-time* gate; the deploy/finalize path trusts the store. Audit posture: after establishing (in a lab) that content staged under policy A boots under policy B, the durable finding is "no revalidation at finalize" — a *separate* defect from the permissive policy itself, and the one that survives the org's remediation. Report both; the second one is why your initial finding keeps its severity after the CVE is patched.
- **Detection on a target (authorized scope):** enumerate staged/bootable deployments (`bootc status`, ostree deployment list) and diff each deployment's image digest against what the *current* policy would accept (`ostree container image store` metadata retains the pull-time verification record — check whether a verification signature exists at all for the running/staged trees). An unsigned staged tree present after a policy-hardening date on the host = the window was live.
- **Attack-chain sequencing for assessments:** poison the tag → trigger/wait for one unattended `bootc-fetch-apply-updates.timer` pull → content is staged → even if the registry is cleaned and the policy hardened in response, the staged tree still boots. Persistence class: boot-path, survives patch, survives rollback (the poisoned tree *becomes* the rollback target). Proof boundary: lab VM only, stop at a `bootc status` showing an unsigned staged tree; never reboot a shared host into unsigned content.
