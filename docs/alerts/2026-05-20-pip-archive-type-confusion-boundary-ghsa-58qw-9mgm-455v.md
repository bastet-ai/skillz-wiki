# pip archive type-confusion boundary

Source: GitHub Security Advisories REST fallback, updated 2026-05-20.

This advisory is durable because it is a supply-chain parser boundary issue in a default Python package installer. A malicious or confusing source distribution can be both a concatenated tar archive and a ZIP archive; affected `pip` versions chose ZIP handling regardless of filename or archive ambiguity, which could make reviewers, mirrors, or policy gates reason about one archive view while installation used another.

## What changed

- **pip archive interpretation conflict** — [GHSA-58qw-9mgm-455v](https://github.com/advisories/GHSA-58qw-9mgm-455v) / CVE-2026-3219: `pip` versions `<= 26.0.1` handled archives that identified as both tar and ZIP as ZIP files, even when the filename or expected package format suggested tar handling. `pip 26.1` only proceeds when an archive identifies uniquely as ZIP or tar.

## Operator triage

1. Upgrade developer workstations, CI images, build runners, and internal packaging jobs to `pip >= 26.1`; do not rely only on application lockfiles, because the vulnerable component is the installer used before dependency resolution completes.
2. Rebuild golden Python base images and cached virtualenv/bootstrap layers that pin or vendor old `pip`. Check `python -m pip --version` inside the same container or runner path that executes installs.
3. Treat locally mirrored source distributions and one-off file installs as higher risk than normal index installs: re-fetch from canonical indexes when possible, verify hashes, and reject archives whose magic bytes or structure do not match the declared type.
4. For sensitive builds, prefer hash-pinned requirements, wheels from a controlled build pipeline, and provenance checks that inspect the exact bytes given to the installer.

## Replayable validation boundaries

- **Installer version gate:** run `python -m pip --version` in every CI/build image; expected result is `26.1` or newer before any package installation step.
- **Polyglot archive rejection:** stage a benign tar/ZIP polyglot package in a test index or local file install path; expected result with patched `pip` is refusal because the archive type is ambiguous.
- **Mirror integrity check:** compare file extension, MIME/type detection, archive magic, and hash for packages served by internal mirrors; expected result is one canonical type and a pinned digest that matches upstream.
- **Build log review:** confirm package installs log the expected artifact URL/hash and that no fallback path silently switches from wheel to source archive without policy approval.

## Durable controls

- Treat package archives as parser inputs with canonicalization requirements, not just compressed blobs. Security checks and installers must agree on the archive view.
- Pin installer/toolchain versions in CI the same way application dependencies are pinned; bootstrap tooling is part of the trusted computing base.
- Prefer wheel promotion pipelines for production builds, with source distributions rebuilt in controlled environments rather than installed directly from untrusted locations.
- Add archive-type ambiguity checks to artifact admission, especially for internal indexes, vendor drops, and emergency dependency overrides.
- Keep supply-chain review focused on the exact artifact bytes consumed by the build, not only the package name/version metadata.
