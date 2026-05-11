# Git scanner, attestation, and build-boundary batch

Source: GitHub Security Advisories updated 2026-05-11.

This batch is durable because it clusters around tooling that defenders and builders often run on untrusted repositories or packages. The core lesson: provenance tools must validate canonical bytes, isolate credentials, and treat human-readable output and build metadata as hostile input.

## Advisories covered

- **go-git malformed-object interpretation and signature mismatch** — [GHSA-389r-gv7p-r3rp](https://github.com/advisories/GHSA-389r-gv7p-r3rp): `github.com/go-git/go-git/v5 <5.19.0` and affected v6 alpha builds can parse malformed commit/tag headers differently from upstream Git and sign or verify reconstructed data instead of raw object bytes.
- **GuardDog remote project scan SSRF and `GH_TOKEN` exfiltration** — [GHSA-587r-mc96-6f2p](https://github.com/advisories/GHSA-587r-mc96-6f2p): `guarddog >=1.0.0,<=2.9.0` rewrites attacker-controlled repository URLs with blind string replacement and can send GitHub credentials to attacker-selected hosts.
- **GuardDog terminal escape injection in human-readable output** — [GHSA-m5p4-gvpx-4mvr](https://github.com/advisories/GHSA-m5p4-gvpx-4mvr): `guarddog >=2.6.0,<=2.9.0` prints attacker-controlled filenames, messages, paths, and snippets without escaping control sequences.
- **Keylime hardcoded push-attestation challenge nonce** — [GHSA-q8w6-w55c-ccv5](https://github.com/advisories/GHSA-q8w6-w55c-ccv5): `keylime >=7.14.0,<=7.14.1` uses a fixed TPM quote challenge nonce, enabling a root attacker on an agent to stockpile quotes and replay them during compromise windows.
- **BentoML Dockerfile command injection via `envs[*].name`** — [GHSA-w2pm-x38x-jp44](https://github.com/advisories/GHSA-w2pm-x38x-jp44): `bentoml <=1.4.38` interpolates environment variable names from `bentofile.yaml` raw into generated Dockerfiles, enabling newline-smuggled `RUN` instructions during `bentoml containerize`.
- **BentoML Dockerfile command injection via `docker.base_image`** — [GHSA-78f9-r8mh-4xm2](https://github.com/advisories/GHSA-78f9-r8mh-4xm2): `bentoml <=1.4.38` renders `docker.base_image` raw in `FROM`, enabling injected Dockerfile directives during container builds.

## Operator triage

1. Patch package scanners, Git libraries, attestation services, and model/app packaging tools used in CI before processing untrusted repositories.
2. Rotate GitHub tokens used by GuardDog-like scanners if they scanned attacker-provided URLs; review proxy, egress, and internal-service logs for `raw.githubusercontent@host`-style requests.
3. Re-run signature/provenance verification with upstream Git or patched go-git for repositories that relied on go-git verification results.
4. Treat untrusted `bentofile.yaml` and `bento.yaml` as build scripts; rebuild only inside isolated workers with no host secrets and no privileged Docker socket.
5. Escape ANSI/OSC/control characters in security scanner output before displaying in terminals, CI annotations, issue comments, or chat bots.

## Durable controls

- URL allowlists must parse the URL and compare canonical scheme, host, and port; never use substring replacement for trust decisions.
- Signature verification should operate over canonical raw bytes, and parsers should reject ambiguous object formats rather than normalizing them silently.
- Attestation freshness depends on unpredictable nonces and verifier-side replay tracking; fixed challenges collapse freshness into historical evidence.
- Generated Dockerfiles must quote, validate, and structurally encode all fields; names and base images are code-adjacent inputs, not inert metadata.
- Human-readable reports need output encoding just like HTML pages: terminal control characters can rewrite screens, links, and logs.

