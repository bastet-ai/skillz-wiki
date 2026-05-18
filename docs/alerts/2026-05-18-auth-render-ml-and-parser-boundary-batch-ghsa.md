# Auth, render, ML, and parser-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-2m69-jmvh-6chr](https://github.com/advisories/GHSA-2m69-jmvh-6chr),
[GHSA-5r97-79vw-qvm4](https://github.com/advisories/GHSA-5r97-79vw-qvm4),
[GHSA-c55g-rp4x-fx84](https://github.com/advisories/GHSA-c55g-rp4x-fx84),
[GHSA-j5rm-v3vh-vx94](https://github.com/advisories/GHSA-j5rm-v3vh-vx94),
[GHSA-qq2p-4282-cfc5](https://github.com/advisories/GHSA-qq2p-4282-cfc5),
[GHSA-74r7-3mjm-jc5v](https://github.com/advisories/GHSA-74r7-3mjm-jc5v),
[GHSA-pf9c-ch8r-2958](https://github.com/advisories/GHSA-pf9c-ch8r-2958),
[GHSA-7wff-wpr6-vmhm](https://github.com/advisories/GHSA-7wff-wpr6-vmhm),
[GHSA-65h7-c7c4-mghx](https://github.com/advisories/GHSA-65h7-c7c4-mghx),
[GHSA-64vr-4gr2-m642](https://github.com/advisories/GHSA-64vr-4gr2-m642),
[GHSA-h2x2-q2mc-24gw](https://github.com/advisories/GHSA-h2x2-q2mc-24gw),
[GHSA-7g5w-pq96-8c5w](https://github.com/advisories/GHSA-7g5w-pq96-8c5w), and
[GHSA-9f4q-q82q-4359](https://github.com/advisories/GHSA-9f4q-q82q-4359).

This batch is durable because it repeats the same boundary failure across very different stacks: rich-content validators that mutate a copy instead of the stored value, one-time auth flows that trust stale challenges or weak transaction isolation, image/XML/model parsers that ingest attacker files, and automation platforms that let user-controlled URLs or commit data drive network requests and shell or pickle execution.

## What changed

- **CI4MS** stored blog content after a broken `html_purify` validation path; sanitized-by-reference content did not propagate, leaving stored XSS reachable by visitors and admins.
- **DirectX Tool Kit / DirectXTK12** spritefont readers in 32-bit builds could hit a multiply overflow when loading untrusted `.spritefont` files. x64/ARM64 native builds are not affected by this specific issue.
- **eduMFA** fixed three auth-state issues: userless Passkey/WebAuthn challenges without expiry, MySQL/MariaDB transaction isolation that could permit one-time token reuse under race, and unauthenticated resolver failcounter increments through `/validate/check`.
- **Statamic Glide** URL validation could be bypassed with non-normalized IP representations, enabling SSRF against loopback, private networks, or cloud metadata when user-supplied URLs reached image proxying.
- **ImageMagick / Magick.NET** fixed an IPTC encoder heap over-read; it is lower-severity, but still belongs in upload/thumbnail parser-hardening queues.
- **MLflow** accepted user-controlled webhook URLs and sent backend requests without sufficient scheme, host, or network allowlisting, creating an authenticated SSRF primitive.
- **automagik-genie** exposed command injection in an MCP server transcript-read path when external `FORGE_BASE_URL` content reached command construction.
- **pgAdmin 4 server mode** added another authorization class: user-owned server groups, servers, background processes, debugger arguments, and shared-server credentials could cross tenant boundaries by guessed IDs or unsafe shared-server helpers.
- **flash-attention** used unsafe `torch.load()` checkpoint loading, so malicious model checkpoints could deserialize arbitrary Python objects.
- **Docling** added another XML parser surface: METS GBS XML extracted from `.tar.gz` archives could trigger entity expansion because parsing did not disable entity resolution.

Withdrawn duplicate advisories for older OpenClaw and WildFly items were observed in the same window and intentionally excluded from new guidance.

## Operator triage

1. Patch priority order:
   - Internet-facing MLflow tracking servers, Statamic image proxy paths, eduMFA deployments, and pgAdmin server-mode consoles.
   - CI4MS authoring/admin workflows where untrusted editors can create blog content.
   - Any service that loads third-party model checkpoints, XML/PDF conversion archives, or image metadata from untrusted users.
2. For eduMFA, upgrade to **2.9.1+**, disable userless Passkey login if immediate patching is blocked, restrict `/validate/check` to trusted client applications, and review MySQL/MariaDB isolation settings for one-time token tables.
3. For SSRF surfaces, validate URLs after canonicalization and again on the final resolved socket address. Block loopback, link-local, RFC1918, metadata, IPv4-mapped IPv6, alternate integer/octal/hex IP forms, redirects, and non-HTTP schemes unless explicitly required.
4. For pgAdmin server mode, treat object IDs as opaque tenant-scoped references. Every Server Group, Server, Shared Server, Background Process, Debugger, and credential helper lookup must include the requesting user or role boundary.
5. For ML/model tooling, do not load checkpoints from untrusted locations with pickle-backed APIs. Prefer safe tensor formats or `torch.load(..., weights_only=True)` where supported, and isolate model warmup/evaluation workers.
6. For XML/archive conversion, apply tar extraction root containment before parsing, disable DTDs and external entities, and set entity-expansion, depth, file-count, and decompressed-size limits.

## Replayable validation boundaries

- **Render boundary:** save `<img onerror>` and SVG/HTML payloads through CI4MS blog content; payloads must be sanitized before persistence or escaped on every render path, including admin preview.
- **One-time auth boundary:** replay expired WebAuthn challenges, race TOTP/HOTP validation under MySQL/MariaDB, and call `/validate/check` with resolver-only inputs; stale/replayed tokens must fail without side effects on unrelated users.
- **URL boundary:** feed decimal, octal, IPv6-mapped, DNS-rebinding, redirecting, and metadata-host URLs through Statamic Glide and MLflow webhook creation; no backend request may reach disallowed networks.
- **Tenant object boundary:** enumerate pgAdmin object IDs from another user; every lookup must return not-found/forbidden before decrypting, displaying, or executing helper settings.
- **Parser boundary:** load malicious `.spritefont`, IPTC image, Docling METS archive, and flash-attention checkpoint fixtures inside disposable workers; crashes, outbound reads, entity expansion, and pickle execution must be blocked or contained.
- **MCP command boundary:** pass shell metacharacters and attacker-controlled commit/transcript values through automagik-genie; command execution must use argv arrays and never concatenate untrusted forge content into a shell.

## Durable controls

- Treat validation functions that mutate by reference as suspect in frameworks that pass copied values; assert on the stored value, not only the validator return.
- Make one-time token consumption atomic at the database boundary and test under the weakest supported transaction isolation.
- Centralize SSRF policy in a resolver that canonicalizes before policy, rechecks after redirects/DNS, and blocks private ranges by default.
- Scope every admin-console object lookup by owner/tenant before use; never authorize after fetching by raw ID.
- Ban unsafe deserialization for model checkpoints and session/cache files unless format, signer, type set, and provenance are controlled.
- Run rich media, XML, archive, and ML parsers in constrained workers with CPU, memory, file, network, and syscall limits.
