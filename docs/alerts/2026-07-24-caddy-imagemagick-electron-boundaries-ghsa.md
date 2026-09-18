---
title: Caddy FastCGI identity, ImageMagick policy, and Electron updater boundaries from July 24 GHSA updates
---

# Caddy FastCGI identity, ImageMagick policy, and Electron updater boundaries from July 24 GHSA updates

This update turns a late GitHub advisory wave into three reusable checks for authorized assessments: HTTP header names that are distinct at an authentication layer can collide after FastCGI normalization; an image operation can read or write paths that the configured ImageMagick policy denies; and Electron update/build helpers can relay credentials across redirect authorities or add the launch directory to runtime search paths.

Sources:

- [GHSA-f59h-q822-g45g / CVE-2026-52845: Caddy FastCGI header normalization bypass in `forward_auth copy_headers`](https://github.com/advisories/GHSA-f59h-q822-g45g)
- [GHSA-82mp-vp5c-9pf7 / CVE-2026-55628: ImageMagick `-concatenate` misses path policy checks](https://github.com/advisories/GHSA-82mp-vp5c-9pf7)
- [GHSA-vghg-5jrg-2398: ImageMagick `-script` misses read-policy checks](https://github.com/advisories/GHSA-vghg-5jrg-2398)
- [GHSA-v3j6-27vc-7pw2: ImageMagick APNG encoder and delegates miss write-policy checks](https://github.com/advisories/GHSA-v3j6-27vc-7pw2)
- [GHSA-56m6-8q75-f2rw: incomplete ImageMagick policy-bypass fix](https://github.com/advisories/GHSA-56m6-8q75-f2rw)
- [GHSA-hc76-7mpc-qjqh: incomplete ImageMagick HTML-encoder code-injection fix](https://github.com/advisories/GHSA-hc76-7mpc-qjqh)
- [GHSA-p2f4-r6v6-j797 / CVE-2026-54673: `builder-util-runtime` relays credential headers across redirects](https://github.com/advisories/GHSA-p2f4-r6v6-j797)
- [GHSA-7g7r-gx96-252g / CVE-2026-54672: Electron AppImage runtime includes empty search-path components](https://github.com/advisories/GHSA-7g7r-gx96-252g)

The same publication wave included ImageMagick parser memory-safety, one-byte debug-profile disclosure, and resource-exhaustion records; an `httplib2` decompression-bomb issue; a LiquidJS memory-accounting bypass; a React Router manifest-endpoint availability issue; and Quinn stream-reassembly exhaustion. They are not expanded here because this page is limited to bounded authorization, filesystem, credential, and execution-boundary validation.

!!! warning "Authorized validation only"
    Use disposable Caddy/PHP-FastCGI fixtures, synthetic identity headers, lab-owned image files, an explicit restrictive ImageMagick policy, two owned redirect origins, fake updater credentials, and a throwaway AppImage launch directory. Do not inject roles into production applications, read or overwrite unrelated files, collect live repository tokens, replace libraries used by real users, or run resource-exhaustion and memory-corruption payloads.

## Operator use

Use these checks when scope includes:

- Caddy deployments that combine `forward_auth`, `copy_headers`, and `php_fastcgi` or another FastCGI backend that trusts `HTTP_*` identity variables;
- image upload, conversion, document-preview, thumbnail, or media-processing paths backed by ImageMagick or Magick.NET;
- applications that expose ImageMagick operations, command fragments, conversion presets, filenames, output destinations, or HTML generation to tenant-controlled data;
- private Electron update channels, especially GitLab-backed channels or custom providers that attach nonstandard credential headers;
- Linux Electron applications distributed as AppImage, particularly when users launch them from shared, downloaded, extracted, or otherwise writable directories.

## Recon checklist

| Boundary | What to trace | Safe canary |
| --- | --- | --- |
| Auth header to CGI variable | Exact header deletion at `forward_auth`, later hyphen-to-underscore conversion, and backend trust in `HTTP_REMOTE_*` | `Remote-Groups` from a lab auth service and client-supplied `Remote_Groups: canary-role` |
| Image operation to policy | Whether every operation performs policy authorization before opening its input and output paths | Synthetic denied input/output paths containing marker text only |
| Image metadata to HTML | Whether attacker-controlled labels, comments, filenames, or properties reach an HTML encoder after incomplete escaping | Harmless HTML attribute/text marker rendered in an isolated page |
| Redirect to credential relay | Header-name case/separator normalization, sensitive-header registry, and behavior when host, scheme, or port changes | Fake `PRIVATE-TOKEN` and mixed-case `Authorization` through two owned origins |
| AppImage environment to loader path | Generated `AppRun`, empty environment variables, trailing/leading separators, current launch directory, and loaded library provenance | Throwaway directory plus an inert constructor that writes one temp marker |

## Caddy `forward_auth` to FastCGI header-collision validation

The failed boundary is not simply “Caddy accepts underscores.” It is a multi-stage representation mismatch:

1. `forward_auth copy_headers Remote-User Remote-Groups` deletes the exact client field names before copying trusted auth-service values.
2. A client field such as `Remote_Groups` is distinct at that deletion step and survives.
3. FastCGI export replaces hyphens with underscores, so `Remote-Groups` and `Remote_Groups` both map to `HTTP_REMOTE_GROUPS`.
4. A PHP/FastCGI application treats the resulting variable as trusted identity or authorization data.

### Lab procedure

1. Build a disposable Caddy configuration with an auth service that returns a synthetic user but deliberately omits an optional group header.
2. Place a minimal FastCGI recorder behind `php_fastcgi`. Have it return only the values of synthetic `HTTP_REMOTE_USER` and `HTTP_REMOTE_GROUPS` variables.
3. Send a baseline request, then repeat with underscore aliases such as `Remote_User` and `Remote_Groups`.
4. Record the raw client fields, auth-service response fields, Caddy/FastCGI environment, and backend decision.
5. Repeat on Caddy 2.11.4 or later. The negative control should reject, remove, or otherwise prevent the alias from influencing the trusted CGI variable.

A strong report proves **client-controlled underscore alias -> survives exact auth-header deletion -> FastCGI normalization collision -> trusted backend role/user variable**. Do not perform privileged actions; a route that returns `role=canary-role` or a harmless authorization decision is sufficient. If an upstream proxy rejects underscore headers, preserve that as a deployment-specific negative control rather than claiming universal reachability.

## ImageMagick operation-policy validation

The concrete `-concatenate` issue is useful as a general review pattern: configuring a deny policy is not proof that every coder and operation consults it at every file-open boundary.

### Preconditions

Confirm all of the following before testing:

- the application reaches ImageMagick or Magick.NET;
- attacker-controlled data can select or influence the relevant operation, input path, output path, script, preset, or wrapper argument;
- the process policy explicitly denies the canary path or relevant path pattern;
- the canary files are inside a disposable lab tree and contain no secrets.

### Lab procedure

1. Create `allowed/` and `denied/` directories under one temporary test root. Put a unique marker file in `denied/` and pre-create a distinct output marker path there.
2. Load a restrictive policy that denies ImageMagick reads and writes for `denied/*`. First prove the policy works through a control operation that performs the expected authorization check.
3. Exercise each operation family the application actually exposes. Use `-concatenate` and `-script` as separate denied-read fixtures; use APNG output and any reachable external-delegate path as separate denied-write fixtures. Never assume that one passing control covers another coder or operation.
4. Capture the policy file, normalized path, operation selected, process arguments or API calls, exit status, and marker-only file result.
5. Compare Magick.NET before and at 14.15.0, or the corresponding fixed ImageMagick build used by the target. Do not infer exposure from package version alone; wrapper reachability and effective policy are required.

For `-script`, use a script file containing only a benign image operation plus a unique marker and prove that the script path itself was denied by policy before testing the vulnerable build. For APNG/delegate output, pre-create a disposable denied destination or inspect a marker-only output under the temporary test root; distinguish a direct APNG encoder write from a delegate-spawned write in the evidence. A useful matrix is:

| Operation family | Policy direction | Expected vulnerable result | Fixed control |
| --- | --- | --- | --- |
| `-concatenate` | denied read or write, tested separately | operation opens the denied canary path | policy rejection |
| `-script` | denied read | marker-only script is consumed | policy rejection |
| APNG encoder | denied write | synthetic APNG appears at denied destination | no output plus policy rejection |
| external delegate | denied write | owned delegate fixture receives denied destination | delegate is not invoked for that path |

Report this as **operation/coder-specific missing policy check -> denied canary path is opened**. Do not read system files, write executable/configuration paths, or substitute a real external command for the delegate fixture. The adjacent incomplete-fix and HTML-encoder records justify testing alternate operation and rendering paths, but their sparse public descriptions do not justify claiming a specific source-to-sink chain without reproducing it. For HTML output, stop at a harmless DOM/text marker and only call it code execution if an executable sink is independently demonstrated in the target viewer.

## Electron updater cross-origin credential relay

`builder-util-runtime` historically removed only an exact lowercase `authorization` property on a cross-origin redirect. GitLab private-update flows can instead use `PRIVATE-TOKEN`; custom callers can use `Authorization`, `AUTHORIZATION`, underscore variants, or other credential headers. The durable check is therefore **authority change plus normalized sensitive-header handling**, not a test for one spelling.

### Two-origin harness

1. Stand up two HTTPS origins you own. Origin A emulates release metadata or an asset endpoint and redirects to origin B; origin B records only header names and fake canary values.
2. Drive the actual application update-check or download path. Use a token with no privileges, such as `PRIVATE-TOKEN: skillz-canary`, and mixed-case fake authorization values.
3. Test same-origin, cross-host, cross-port, HTTPS-to-HTTPS, and—only in a local harness—scheme-change redirects.
4. Record which fake headers reach origin B and whether a redirect can be influenced by release metadata, provider responses, an owned package registry, or an application-controlled custom feed.
5. Repeat with `builder-util-runtime` 9.7.0 / electron-builder 26.15.0 or later.

Evidence should be a decision table, for example:

| Redirect | Header spelling | Reached origin B? |
| --- | --- | --- |
| same origin | `PRIVATE-TOKEN` | expected by application design |
| cross origin | `PRIVATE-TOKEN` | must be stripped |
| cross origin | `Authorization` | must be stripped case-insensitively |
| cross origin | app-specific fake secret header | document actual policy |

Do not direct a real update client carrying a live GitLab PAT to a collection endpoint. A fake token through the same provider code path is enough to prove the leak.

## Electron AppImage current-directory search-path validation

The AppImage issue arises when generated `AppRun` code appends an unset variable unconditionally:

```bash
export LD_LIBRARY_PATH="${APPDIR}/usr/lib:${LD_LIBRARY_PATH}"
```

If `LD_LIBRARY_PATH` is unset, the trailing colon is an empty path component. The dynamic loader interprets that component as the current working directory. Similar empty-component reasoning applies to `PATH`, `XDG_DATA_DIRS`, and `GSETTINGS_SCHEMA_DIR`, but library-load provenance is the highest-value validation path.

### Disposable proof

1. Build a benign test Electron AppImage with the same `app-builder-lib` version as the target artifact, or inspect the distributed artifact's `AppRun` without executing it.
2. Launch from a throwaway directory while relevant environment variables are unset. Record the effective `LD_LIBRARY_PATH` and whether it contains an empty component.
3. If execution proof is explicitly authorized, identify one non-sensitive library name loaded by the test app and place an inert lab library with that name in the throwaway launch directory. Its constructor should write one marker under the same temporary root and perform no other action.
4. Capture loader provenance with a local mechanism such as `LD_DEBUG=libs`; redact unrelated host paths if needed.
5. Rebuild with `app-builder-lib` 26.15.0 or later and show that the environment expression uses conditional separator insertion and no longer searches the current directory.

A report must establish **vulnerable generated runtime + writable launch directory + predictable library lookup + marker loaded with the AppImage user's privileges**. Package-version presence alone is not enough, and this is not privilege escalation unless the AppImage is launched by a more privileged user from an attacker-writable directory.

## Reporting notes

Lead with the exact boundary and prerequisites:

- **Caddy exact HTTP-field cleanup -> FastCGI canonicalization -> identity-variable collision**;
- **ImageMagick deny policy -> operation-specific missing authorization -> canary read/write outside the allowed path set**;
- **Electron updater redirect authority changes -> non-normalized sensitive-header filter -> fake credential relay**;
- **generated AppImage environment -> empty search-path component -> current-directory library load**.

Include raw request/header evidence, normalized representations, effective versions, configuration, and a fixed-version negative control. Keep availability-only and memory-safety advisories separate unless the target exposes a bounded, replayable, explicitly authorized path that provides more than a crash.

## September 18 follow-up: Caddy replacer-layer double-expansion, hide-directive case bypass, and body-placeholder buffering (GHSA-j8px-rmrx-76h9 / CVE-2026-77281, fixed 2.11.4)

Source: [GHSA-j8px-rmrx-76h9 / CVE-2026-77281: Caddy rewrite placeholder re-expansion, unbounded body buffer, and fileHidden case-sensitivity bypass](https://github.com/advisories/GHSA-j8px-rmrx-76h9) — bundled advisory verified end-to-end against the official `caddy:2.11.3` image.

Three durable operator lessons from the placeholder/replacer layer:

1. **Placeholder/template re-expansion is a regression family, not a one-off.** When a `rewrite` URI template contains a request-data placeholder **and** ends with a trailing `?`, the first replacer pass expands attacker header bytes into the query component, and `buildQueryString` runs a **second** replacer pass over those bytes — resolving placeholders the attacker injected. `X-Fwd: foo?{env.DATABASE_URL}=leak` exfiltrates any env var into the request URL (access logs, `reverse_proxy` forwarding, `{http.request.uri.query}` downstream), plus `{file./path}` and `{vars.X}` primitives. This is the **exact gadget previously patched in `vars_regexp` (CVE-2026-30852)** — the fix did not extend to `rewrite` and no regression test was carried over. Audit rule: after any framework bug fix in a template/placeholder engine, enumerate every *other* directive that reaches the same expansion function and test the unpatched siblings first (`rewrite`, header forwarding, CEL matchers, third-party modules). Grep the fix commit's sibling files, not just the patched file.
2. **`hide` directives are matched case-sensitively while the filesystem may not be.** `fileHidden()` uses case-sensitive `filepath.Match`, but macOS APFS and Windows NTFS resolve `/.GIT` and `/.git` to the same tree — the hide rule provides zero protection for `.git`, `.env`, `secrets` on those hosts (and Linux `casefold`/mixed-case side-by-side dirs leak too). Recon heuristic for any static-file server on a suspected macOS/Windows host (or any host with build/backup pipelines): **before concluding a hidden path is absent, re-request every case variant** (`.GIT/HEAD`, `.ENV`, `Secrets/`), and diff the 404-vs-200 decision table against the exact-case probe. A 200 on a case variant with the 404 on the literal is dispositive parser/case-split evidence.
3. **Placeholder-driven body reads bypass the platform's own size limit.** `{http.request.body}` resolution reads the whole body with no `LimitReader`, and the `needsEarly` path resolves it *before* `request_body` middleware applies `max_size` — the documented `log_append body {http.request.body}` debug pattern becomes host/cgroup RAM exhaustion (OOMKilled=137 in the lab fixture). Operator value is the general rule: when a framework resolves request content eagerly for observability features, its configured limits may not apply to that leg; probe limit behavior per feature (logging, CEL match, header forwarding), not per endpoint. (Availability-only; no persistence.)

Lab validation on an authorized Caddy ≤2.11.3: minimal Caddyfile with `rewrite * /serve/{http.request.header.X-Fwd}?` and a fake `DATABASE_URL` env; single request with the injected `{env.DATABASE_URL}` query payload; evidence = URL-decoded query showing the fake secret. Case-bypass fixture: temp tree with `.git/` + `.GIT/` (or one dir on a case-insensitive host) plus `hide .git`, then the exact-vs-variant status table. All payloads fake-value, containerized, no egress. Report the re-expansion finding as **operator-config precondition (trailing-`?` template) + header-controlled placeholder → secret-shaped bytes into URL/log/upstream channel**, and the case finding as **hide-rule matcher vs filesystem case semantics split → "hidden" high-value paths served**. Fixed-version control: Caddy 2.11.4.