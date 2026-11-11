---
title: Git config, template, OAuth, and object-path boundaries from July 24 GHSA updates
---

# Git config, template, OAuth, and object-path boundaries from July 24 GHSA updates

A late July 24 advisory wave adds four reusable checks: repository metadata serialized into trusted Git configuration, server-side template property reads that recover the JavaScript `Function` constructor, OAuth URL globs that cross authority/path boundaries, and dotted update paths that mutate `Object.prototype` during Mongoose casting.

Sources:

- [GHSA-3rp5-jjmw-4wv2: GitPython same-line config section injection](https://github.com/advisories/GHSA-3rp5-jjmw-4wv2)
- [GHSA-7gfh-x38p-prh3: Velocity.js property-read sandbox bypass](https://github.com/advisories/GHSA-7gfh-x38p-prh3)
- [GHSA-38hq-7x33-php4: Backstage experimental OAuth redirect allowlist bypass](https://github.com/advisories/GHSA-38hq-7x33-php4)
- [GHSA-664h-wqgq-64gw: Mongoose update-casting prototype pollution](https://github.com/advisories/GHSA-664h-wqgq-64gw)

!!! warning "Authorized validation only"
    Use disposable repositories and Git configuration, inert template counters, owned OAuth clients/origins and fake authorization codes, and fresh Node processes with synthetic Mongoose updates. Never trigger an injected Git command, run a template shell payload, collect real authorization codes, modify production records, or test process-global prototype changes in shared workers.

## GitPython submodule name to repository config

GitPython through 3.1.52 rejected CR, LF, and NUL in config names, but a same-line section/subsection name could contain bracket, quote, space, and comment syntax. A submodule name from `.gitmodules`, or from an application calling `Repo.create_submodule(name=...)`, could therefore close the intended `[submodule "..."]` header and inject another Git configuration directive into the parent repository's trusted `.git/config`. GitPython 3.1.53 adds the fix.

### Parse-only proof

1. Create a disposable parent repository and a benign local bare repository to use as the submodule URL. Set temporary `HOME`, `GIT_CONFIG_GLOBAL`, and `GIT_CONFIG_SYSTEM` values so no host configuration is read or changed.
2. Add a control submodule with a normal name and inventory the resulting `.git/config`.
3. In a fresh parent, use a name shaped to close the quoted submodule section and introduce an inert key such as `skillz.marker=canary` in a second section on the same line. Do not inject `core.sshCommand`, `alias`, pager, hook, or filesystem-monitor values.
4. Read the raw config and use `git config --get skillz.marker` as a parser oracle. Do not run fetch, pull, push, aliases, pagers, hooks, or any command that could realize an executable config sink.
5. Repeat both through the direct `create_submodule` path and, when in scope, clone plus `submodule_update(init=True)` using a fully local hostile fixture.
6. Confirm GitPython 3.1.53 rejects or safely encodes the name.

Strong evidence is **attacker-controlled submodule name -> GitPython emits a second same-line config section -> native Git parses a marker directive from trusted repository config**. Explain that executable directives can create RCE on later Git operations, but keep the proof parse-only.

## Velocity.js property-read to `Function`

The earlier Velocity.js fix blocked `__proto__`, `constructor`, and `prototype` on `#set` assignment targets. In 2.1.6, read expressions remained unfiltered, so a template could traverse an ordinary object's constructor chain to JavaScript's `Function` constructor, build a function, and invoke it. Version 2.1.7 closes the read path.

### No-shell renderer harness

1. Confirm the application renders attacker-controlled Velocity template syntax, not merely data values in a trusted template.
2. In a local harness, expose an empty object and a test-only global counter function. The marker function must only increment memory or append to a temp event list.
3. Use a template expression that reads constructor properties and constructs a function whose body calls only the marker counter. Do not reference `process`, `require`, environment variables, child processes, filesystem, or network APIs.
4. Capture the template AST/property-read trace, constructor identity, marker count before/after render, rendered output, and version.
5. Test direct output expressions and right-hand expressions separately if both are reachable. Do not assume the `#set` target fix covers property reads elsewhere.
6. Repeat on 2.1.7 and with trusted-template/untrusted-data controls.

Report **attacker-controlled template -> inherited `constructor.constructor` property reads -> dynamic Function creation -> inert server-process side effect**. If users only control interpolation data, the advisory's template-control precondition is absent.

## Backstage OAuth URL-component glob confusion

The vulnerable behavior is limited to `@backstage/plugin-auth-backend` through 0.29.1 when experimental dynamic client registration or client-ID metadata documents are explicitly enabled with custom patterns. Defaults and disabled features are not affected. Matching a glob against the entire URL allowed a hostname wildcard to consume `/` and path text, protocol-less patterns to match unintended schemes, and credential-bearing URLs to be normalized before matching.

### Two-origin registration matrix

Use a test Backstage instance, an owned trusted-pattern domain, an owned attacker-control domain, a disposable OAuth client, and authorization codes containing no user authority beyond a canary profile.

| Pattern/input | What to vary | Expected decision |
| --- | --- | --- |
| `https://*.trusted.example/callback` | true subdomain vs attacker host whose path contains `.trusted.example/callback` | only true subdomain allowed |
| protocol-less custom pattern | `https`, `http`, and non-HTTP scheme | configuration rejected or exact intended scheme only |
| credential-bearing redirect | `https://user:pass@owned.example/callback` | rejected, not stripped then matched |
| loopback with wildcard port | root path vs non-root path | document 0.29.2 component semantics |

1. Record feature flags and the exact custom allowlist; package presence alone is insufficient.
2. Attempt client registration or metadata-document resolution with each owned URL.
3. If an unintended redirect is accepted, run one authorization flow using a disposable user and intercept only a fake/canary code at the owned destination. Do not redeem a real user's code or token.
4. Repeat on plugin-auth-backend 0.29.2.

The chain is **custom full-URL glob -> wildcard crosses authority/path component -> attacker-owned redirect accepted -> canary authorization code delivered to wrong origin**. State which experimental feature and pattern made it reachable.

## Mongoose dotted update-path prototype mutation

In affected Mongoose 6.x through 9.x lines, casting a user-controlled update such as an own `$set` key beginning `__proto__.` could assign internal schema metadata (`$fullPath` and `$parentSchemaDocArray`) onto `Object.prototype`. The cast may throw after the mutation, so an error response does not prove the process state remained clean. Fixed releases are 6.13.10, 7.8.10, 8.24.1, and 9.7.2.

### Fresh-process state proof

1. Start a one-shot Node process with a minimal schema and no database connection required beyond the actual application path under test.
2. Build the update with `JSON.parse()` so `__proto__` is an own data property; avoid JavaScript object-literal semantics that may instead alter only the payload object's prototype.
3. Snapshot own/enumerable properties on `Object.prototype` and a fresh `{}` before casting.
4. Send only a marker update path and invoke the same update casting path the application reaches. Catch errors, then snapshot process-global prototype state again.
5. Test downstream impact only with an inert policy object in the same disposable process,for example, whether an inherited marker changes a synthetic branch. Do not mutate authorization, shell, template, or database behavior.
6. Exit the process after every case. Repeat with the appropriate patched release and with update sanitization enabled.

A valid finding proves **attacker-controlled update object -> dotted `__proto__` path reaches schema lookup/casting -> Mongoose writes enumerable internal fields onto `Object.prototype` despite an eventual throw**. Do not call this arbitrary prototype pollution unless attacker control over property names/values beyond the confirmed internal fields is independently shown, and do not claim privilege escalation without a concrete reachable downstream consumer.

## Reporting notes

Lead with the exact boundary and trigger:

- submodule/config section name to repository-local Git directive;
- template property read to dynamic function construction;
- OAuth full-string glob to mismatched URL authority;
- own dotted update key to process-global prototype metadata.

Include version, route/API, attacker-control provenance, raw and parsed representations, side-effect timing, patched negative control, and marker-only evidence. Keep all proofs in disposable, single-purpose environments.

## Late follow-up: Prompty Nunjucks template member access

[GHSA-w28w-gp39-m4p6](https://github.com/advisories/GHSA-w28w-gp39-m4p6) adds the same high-level read-to-constructor lesson as Velocity.js to a distinct AI prompt-template surface. Affected `@prompty/core` TypeScript runtimes through 0.1.4 and 2.0.0-beta.4 render `.prompty` bodies with Nunjucks member access that can traverse constructor/prototype properties and invoke functions in the host Node.js process. The patched 2.0.0-beta.5 renderer restricts inputs to own data, blocks constructor/prototype traversal, and disallows template function calls while retaining ordinary interpolation, loops, and conditionals.

### Prompty-specific reachability

Confirm the application renders `.prompty` files through the TypeScript runtime and that an attacker can influence the **template body**, not only ordinary prompt variables. Relevant sources include community prompt packages, cloned repositories, uploaded prompt definitions, agent-generated templates, or marketplace content. A Python runtime, trusted template with untrusted scalar values, or package presence without rendering is not enough.

### Inert renderer proof

1. Run `@prompty/core` in a disposable Node process with a local `.prompty` file and synthetic render data.
2. Give the test data one inert function that increments an in-memory counter; expose no process, filesystem, environment, shell, package-manager, or network capability.
3. Establish ordinary interpolation, conditional, loop, and own nested-property controls.
4. Attempt constructor/prototype member traversal and a call to the inert counter through the same default or explicit Nunjucks renderer the application uses.
5. Record the parsed template body, member lookup sequence, function-call decision, counter before/after, and rendered marker.
6. Repeat on 2.0.0-beta.5 or later. Ordinary data rendering should remain functional while unsafe member lookups and calls fail.

Report **attacker-controlled `.prompty` body -> unrestricted Nunjucks member traversal -> function object reached/called -> inert host-process side effect**. Do not use a shell command, read environment variables, install packages, or test untrusted prompts on an agent host carrying real credentials.

## Late follow-up: GitPython option transformation and diff output

GitPython 3.1.54 closes three additional argument-boundary gaps affecting 3.1.53 and earlier:

- [GHSA-r9mr-m37c-5fr3](https://github.com/advisories/GHSA-r9mr-m37c-5fr3): a single-character kwarg can place its value in a second argv token, so the safety check sees only `-n` while Git later sees a smuggled long option;
- [GHSA-6p8h-3wgx-97gf](https://github.com/advisories/GHSA-6p8h-3wgx-97gf): clone's unsafe-option denylist omits `--template`, allowing a supplied template directory to contribute executable hooks; and
- [GHSA-fjr4-x663-mwxc](https://github.com/advisories/GHSA-fjr4-x663-mwxc): `Diffable.diff()` has no unsafe-option guard, and both `output=` and an `other` value beginning with `--output=` can select and overwrite a filesystem path.

### Argv-only and marker-file proof

1. Confirm the application forwards user-controlled option dictionaries, clone template paths, diff kwargs, or revision-like `other` values into the named GitPython APIs. A hard-coded option is not remotely reachable.
2. Monkeypatch or wrap the Git command runner in a disposable test so it records final argv and performs no command. Compare the candidates inspected by the guard with the transformed argv.
3. For the single-character case, use a fake long option marker rather than `--upload-pack`; prove that an extra option-shaped token appears after the guard approved only the short key.
4. For clone templates, stage an owned local template whose `post-checkout` hook writes one fixed marker under the temp root. Clone only a local synthetic repository under a temporary `HOME`.
5. For diff output, target an existing canary file in the temp root and generate a harmless one-line repository diff. Test key control and `other` value control separately.
6. Repeat on 3.1.54. Unsafe transformed tokens and templates must be rejected, and diff arguments must not overwrite the canary.

Evidence should bind **untrusted Python argument -> transformed native Git argv -> inert hook or selected canary write**. Never target SSH files, shell profiles, Git config, application config, or production repositories, and do not execute an upload-pack command.

## Late follow-up: GitPython remote URL environment expansion

[GHSA-94p4-4cq8-9g67](https://github.com/advisories/GHSA-94p4-4cq8-9g67) shows that the earlier clone-path fix did not cover `Repo.create_remote()`, `Remote.add()`, or the sibling submodule-add path. Through GitPython 3.1.53, these callers retained `Git.polish_url(..., expand_vars=True)`, so an attacker-influenced URL containing an environment placeholder could be expanded by the hosting process, written into `.git/config` or `.gitmodules`, and sent on a later fetch. Version `3.1.55` is the fixed control.

Use a temporary repository, a single fake environment variable, and an owned local HTTP listener. First prove expansion parse-only by inspecting the remote URL and recording only whether the fixed sentinel appears; then, if network execution is explicitly in scope, perform one fetch to the local listener and preserve a hash/redacted path marker. Clear the environment and delete the repository afterward. The finding is **untrusted remote/submodule URL -> host environment interpolation -> persistent Git URL -> later owned callback**. Never seed real cloud tokens or inspect an existing repository's remotes.