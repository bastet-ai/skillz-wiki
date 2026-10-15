# GitPython unsafe-option, config-reserialization, and merge-include boundaries

Source: GitHub Security Advisories `unreviewed` feed, 2026-08-25 (all first published 2026-08-25): [GHSA-9557-234j-7rv9](https://github.com/advisories/GHSA-9557-234j-7rv9) (config multi-line write reserialization, critical 9.8), [GHSA-crmc-f4m7-33fj](https://github.com/advisories/GHSA-crmc-f4m7-33fj) (`.gitmodules` merge-includes file disclosure, high 8.4), [GHSA-7r39-6q8m-qw68](https://github.com/advisories/GHSA-7r39-6q8m-qw68) (`--separate-git-dir` clone redirect, high 7.5), [GHSA-89ff-m8wv-p99r](https://github.com/advisories/GHSA-89ff-m8wv-p99r) (`blame` `--contents`/`-S` file read, high 6.5), and [GHSA-6rj2-96f5-chj9](https://github.com/advisories/GHSA-6rj2-96f5-chj9) (`TagReference.create` `--file` file read, high 6.5). All affect `GitPython` before `3.1.59`.

This wave is durable because it exposes a reusable pattern: a Python wrapper around the `git` CLI builds an argv list from caller-controlled fields (revision strings, tag refs, clone target dir, config values, submodule files) and a denylist of "unsafe" leading-dash options is incomplete or is bypassed by a secondary code path. When a library accepts a repository it does not own — a clone target, a submodule `.gitmodules`, a packed `config`, a blame ref — an attacker who controls that repository content can inject git options that read files, write directories, or arm a later code-execution hook. The same boundary recurs across every wrapper around `git` (Go `go-git`, `dulwich`, `libgit2` bindings, CI job specs), so the check generalizes.

!!! warning "Canaries only"
    Run these checks against disposable local repositories and a scratch filesystem root. Use marker files, inert hooks, and a denied hook-execution sink. Never read credentials, shell startup files, cloud metadata, or real repo internals, and never execute an attacker-injected `core.hooksPath` payload on a shared host.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| `Repo.blame` | revision string with `--contents=` / `-S` | library passes it to `git blame` and returns the result | mocked git records a denied `--contents` option; no outside-root file is read |
| `TagReference.create` | positional reference with `--file=` | library passes it to `git tag`/`git cat-file` | mocked git records a denied `--file`; tag message is a fixed canary |
| `Repo.clone_from` / `clone` | `separate_git_dir` argument | library adds `--separate-git-dir` outside the intended clone root | clone sink creates metadata only inside the disposable root |
| `config` write | multi-line value with embedded newline | reserialization turns a dormant quoted value into a live `core.hooksPath` directive | written config is re-parsed and the injected directive is absent or inert |
| `.gitmodules` | `[include]` directive pointing at a file | parser raises an error that embeds the target's first line | include is disabled; the raised error contains no outside-root content |

Prove the option-acceptance edge and the final sink separately. A leading-dash value that is merely accepted by the library is not enough; preserve the argv the library would hand to `git`, the resolved target file or directory, and the returned marker.

## Git option injection via library argv

The recurring primitive is that a field the library treats as "just a value" can carry a git option because it is concatenated into argv without the leading-dash guard.

1. Stand up a disposable repository and an instrumented `git` shim on `PATH` that records argv and returns a fixed marker instead of touching the real repo.
2. Drive each library entry point with an ordinary value, then with one option-shaped marker:
   - `Repo.blame(rev="--contents=<marker>")` and `blame(..., -S shaped)`;
   - `TagReference.create(repo, "--file=<marker>")`;
   - `Repo.clone_from(url, target, separate_git_dir=<outside-root-marker>)`.
3. Record, for each, the exact argv, whether the unsafe option survived the library's denylist, and the file/directory the option would resolve to.

| Input class | Expected secure result |
| --- | --- |
| ordinary ref/path | passed through as a single value, no option |
| `--contents`/`-S`/`--file`/`--separate-git-dir` marker | rejected, quoted, or resolved inside the declared root |
| leading-dash control character | never forwarded as a separate argv token |

The strongest evidence is a denied argv showing the marker token was stripped or contained, paired with a fixed-version control where the same input is accepted. Do not point `--contents` at `/etc` or credentials; use a sibling marker file inside the disposable root.

## `--separate-git-dir` clone redirect

`--separate-git-dir` is dangerous because it relocates repository metadata (including `hooks/`) to an attacker-chosen path. In a lab:

1. Configure the clone destination inside a disposable root and pass a `separate_git_dir` that escapes it.
2. Record the destination git-dir the library computes and whether it lands outside the root.
3. If the metadata path is outside the root, stop at the recorder — do **not** populate or run hooks there.

A bounded positive is the computed git-dir escaping the disposable root. Report the directory-redirection primitive and note that hook execution is the downstream risk only if the attacker also controls the metadata tree; do not claim RCE without a separate authorized inert sink proving hook invocation.

## Config multi-line write reserialization to hook execution

This is the highest-impact item. `git config` stores multi-line values as indented continuation lines; a library that re-serializes a value by naively re-emitting it can turn a *dormant* quoted value into a live directive.

1. Seed a repository `config` with a value that contains an embedded newline and a quoted `core.hooksPath` segment, using a disposable hooks directory marker.
2. Invoke an *unrelated* GitPython config write (any key, any value) through the affected API.
3. Re-read the written `config` and confirm whether the embedded newline survived as a real separator that activates `core.hooksPath`.

| Control | Expected secure result |
| --- | --- |
| single-line value | round-trips unchanged |
| multi-line value with directive | re-serialized so the directive stays quoted/inert |

The bounded positive is the written file containing a live `core.hooksPath` pointing at the disposable marker after an unrelated write. **Do not run the hook.** Prove the reserialization drift with the file content and a denied hook-execution recorder; execution of an attacker path on a shared host is out of scope.

## `.gitmodules` merge-includes disclosure

`git` merges `[include]` sections from submodule configs by default; a library that parses `.gitmodules` without disabling `merge_includes` will read the included file and can echo part of it in an error.

1. Plant a `.gitmodules` containing an `[include]` directive that points at a sibling marker file inside the disposable root.
2. Access `repo.submodules` (or the equivalent submodule-enum API) and capture the raised `MissingSectionHeaderError`.
3. Check whether the exception message embeds the marker's first line.

A positive is the outside-root (or sibling) marker content appearing in the error string. Report the include-disclosure primitive with the directive and the embedded line; never include the contents of a real sensitive file in the report.

## Reporting heuristics

- Frame each finding around the specific library entry point and the argv it would hand to `git`: "GitPython `Repo.blame` forwards `--contents` from a caller-controlled revision to the git CLI."
- Separate the primitive (file read / directory redirect / config injection) from the impact (disclosure / hook execution). Only the config-reserialization item reaches a plausible code-execution path, and only via a later hook invocation that must be proven independently.
- Cite the version bound (`< 3.1.59`) and note that all five are mitigated by a complete unsafe-option denylist plus disabling `merge_includes` on submodule config parsing.

## Safety

- Authorized, in-scope targets only; these wrappers frequently run in CI/CD and build agents where the "attacker-controlled repo" is a cloned dependency.
- Use instrumented git shims and denied sinks so the check records intent without touching real files or executing hooks.
- No credential, shell-startup, or cloud-metadata reads; marker files only inside a disposable root.
- Do not run injected `core.hooksPath` payloads or `--separate-git-dir` hooks on shared or production hosts.

## October 15 follow-up: seven-GHSA coordinated wave to 3.2.0 — guard-scope misses positional args, alternate transports, and lexical-only checks (CVE-2026-110855..110860)

GitPython published a **seven-advisory coordinated wave** at 00:31Z (all fixed **3.2.0**, a major-boundary fix — the vendor rebuilt the unsafe handling rather than appending to the denylist, confirming this page's "incomplete denylist" root-cause read). Second GitPython wave on this page; re-sweep rule validated again. New legs:

| Advisory | Leg | New axis |
| --- | --- | --- |
| [CVE-2026-110858 / GHSA-mcf4-6385-6rcq](https://github.com/advisories/GHSA-mcf4-6385-6rcq) (critical) | `Remote.pull()` RCE: the unsafe-option guard **inspects only keyword arguments, not the positional refspec** — `--upload-pack=<command>` via refspec executes OS commands over local-path or SSH transports | **Guard-scope vs positional args**: an unsafe-argument check that only walks named parameters leaves every positional pass-through unguarded. Fuzz each API with option-shaped values in *positional* slots, not just kwargs. |
| [CVE-2026-110857 / GHSA-jj45-mj3g-556c](https://github.com/advisories/GHSA-jj45-mj3g-556c) (high) | `Git.ls_remote` forwards URLs **without `check_unsafe_protocols`** → `ext::` remote-helper RCE; `merge_base`/`IndexFile.move` also accept unguarded option injection | **Per-entry-point guard parity**: the library *has* a protocol guard; it just isn't called on every URL-consuming entry point. Enumerate all URL/option-consuming APIs (`ls_remote`, `fetch`, `pull`, `clone`, `merge_base`, `.move`) and diff which ones invoke the guard — grep `check_unsafe` call sites vs `Git()` invocations. |
| [CVE-2026-110859 / GHSA-pv89-gqgv-pcc9](https://github.com/advisories/GHSA-pv89-gqgv-pcc9) (high) | `Head.checkout()` argument injection: a default branch **named `--pathspec-from-file=<path>`** makes clone-and-checkout apps leak file contents through `GitCommandError` messages | **Repository-content-as-option**: branch names (not just refs passed by the app) become argv — the attacker controls the *default branch name* of the cloned repo. New carrier for the existing argv table; also a clone-time fingerprint: any tool that auto-checks-out the active branch of an untrusted repo inherits this. |
| [CVE-2026-110855 / GHSA-cwpg-5qqf-hf36](https://github.com/advisories/GHSA-cwpg-5qqf-hf36) (high) | `Repo._clone()` omits `expand_vars=False` when polishing `separate_git_dir` → a `.gitmodules` submodule **name containing `$VAR` syntax** gets environment-variable-expanded, exposing secrets in `.git/modules` directory names and DEBUG logs | **Env-expansion in path polish**: git's own `expand_vars` semantics leak through when the wrapper reuses git's URL/dir polish on attacker-named objects. Check any `.gitmodules` *name* (not just URL) as a template sink; grep `expand_vars`/`os.path.expandvars` on repository-derived strings. |
| [CVE-2026-110860 / GHSA-cfp4-478m-4f52](https://github.com/advisories/GHSA-cfp4-478m-4f52) (medium) | `Submodule.move()` checks destination **lexically only** — committed symlink `vendor/` outside the worktree relocates the checkout externally, corrupting index and `.gitmodules` | Lexical-prefix containment without `O_NOFOLLOW`-equivalent link resolution — same family as the July 28 extraction page and the Oct 15 Gitingest symlink leg (both repo-ingestion carriers). |
| [CVE-2026-110856 / GHSA-f52j-wg44-2h83](https://github.com/advisories/GHSA-f52j-wg44-2h83) (high) | `_re_actor_epoch` ReDoS on author/committer/tagger lines (long space-filled lines, no valid epoch/timezone → quadratic backtracking) | Tracked: parser-DoS class, no operator surface beyond fingerprinting crafted commit identities. |

Wave-level rule: **a major-version rewrite of the guard layer marks the denylist era as dead** — apps that pinned `<3.2.0` and monkey-patched the old denylist are still exposed on the new positional/protocol legs; apps on 3.1.x are exposed on all seven. For any git-wrapper audit (go-git, dulwich, libgit2 bindings, CI job specs), re-run this page's argv recorder battery with (1) positional option-shaped values, (2) `ext::`/`--upload-pack` shapes per entry point, (3) attacker-named default branches, and (4) `$VAR` in submodule names.

## Reviewed but not promoted here

The adjacent GitPython CVE records in the same wave have no separate operator surface beyond the five boundaries above and are tracked in the source index.
