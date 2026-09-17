# Archive extraction traversal and link-boundary validation

Archive extraction is a common supply-chain and scanning surface (tar/zip/deb/rpm). A frequent failure mode is allowing paths or symlinks that escape the intended extraction directory.

## Threat model

An attacker provides an archive that, when extracted, causes:

- writes outside the target directory via `../` traversal or absolute paths
- writes outside the target directory via symlinks (create symlink inside dir → write through it)
- overwriting sensitive files (cron, SSH keys, config) when running as a privileged user

This matters even for “just scanning” workflows: if your scanner extracts untrusted archives, it’s part of your attack surface.

## Defensive extraction rules (portable)

### 1) Canonicalize and validate every member path

Reject entries when any of the following are true:

- path is absolute (`/etc/passwd`, `C:\\Windows\\...`)
- path contains `..` segments after normalization
- normalized path does not stay under the extraction root

### 2) Handle symlinks explicitly (don’t trust defaults)

- If you don’t need symlinks: **do not create them** (treat as suspicious and skip).
- If you allow symlinks:
  - validate the symlink *location* is within the root
  - validate the symlink *target* resolves within the root
  - on write operations, ensure you’re not writing through a symlink (use `O_NOFOLLOW` where available)

### 3) Prefer “openat-style” safe extraction

Where supported:

- open the root directory FD
- for each path segment, use `openat()` / `mkdirat()` with `O_NOFOLLOW`
- never follow symlinks while traversing

This avoids TOCTOU races and is far more robust than string checks.

### 4) Run extraction in a sandbox

Even with safe extraction, reduce blast radius:

- run as an unprivileged user
- extract into a temp directory on a dedicated filesystem
- consider container / namespace isolation (especially in CI)

## Quick regression tests

Include archives that attempt:

- `../../escape.txt`
- `/etc/cron.d/pwn`
- create `subdir/link -> ../../..` then write `subdir/link/escape`

Your extractor should either reject them or extract safely without writing outside root.

## GNU tar hardlink and restore-race operator matrix

Two August 2026 GNU tar records show why a `../`-only archive test is incomplete:

- [GHSA-4f5j-wqjr-hx49 / CVE-2026-18508](https://github.com/advisories/GHSA-4f5j-wqjr-hx49) describes a `--one-top-level` hardlink target resolving relative to the extraction working directory and composing with a pre-existing symlink; and
- [GHSA-v7fx-gjvh-347c / CVE-2026-18477](https://github.com/advisories/GHSA-v7fx-gjvh-347c) describes a TOCTOU condition in incremental `dumpdir` rename restoration where an actor able to modify the restored directory can influence later creates, renames, or overwrites outside the intended root.

Use a disposable mount namespace or temporary filesystem containing only random marker files. Record syscalls and canonical paths; never target an operational backup, restore host, home directory, or privileged path.

| Case | Controlled change | Evidence to capture |
| --- | --- | --- |
| ordinary file | regular member below a new `--one-top-level` root | expected `openat`/write remains below root |
| hardlink baseline | hardlink to an earlier in-root regular member | link source and destination remain below root |
| hardlink authority | hardlink target interpreted relative to extraction CWD | lexical target, effective CWD, canonical source/destination |
| pre-existing symlink composition | one disposable CWD component points to a sibling canary directory | `lstat`, `readlink`, and attempted link/write path; abort before replacing the canary |
| incremental rename baseline | fixed dumpdir metadata with no concurrent mutation | rename sequence stays below root |
| rename race | helper swaps only a random disposable directory component at a synchronization barrier | inode/dev before check and use, rename/open destination, escaped-path decision |
| corrected build | replay the identical archive and schedule | outside-root operations are rejected |

For the race case, use a deterministic interposer or debugger barrier rather than an unbounded timing loop. Patch or deny the final outside-root `renameat`, `linkat`, or open syscall while still recording its arguments. A safe positive is **approved extraction root -> hardlink/rename state resolves through a changed or CWD-relative component -> syscall recorder observes a canonical destination at the sibling canary**. Do not require an actual overwrite.

Keep the preconditions distinct. CVE-2026-18508 requires archive-controlled hardlink metadata plus relevant pre-existing filesystem state. CVE-2026-18477 concerns incremental restore state and an actor able to modify the restore tree at the required time; it does not require a crafted archive. Report exactly which primitive and environmental authority were proven.

## CPython relocation and platform-path matrix

Three CPython records add reusable cases for any wrapper that treats a standard-library extraction filter as the whole security boundary:

- [GHSA-9mc4-rqmq-h467 / CVE-2026-11940](https://github.com/advisories/GHSA-9mc4-rqmq-h467) describes an incomplete `tarfile` fix. A hardlink names a deeper archived symlink, fallback processing validates the symlink at that deeper name, and then recreates it at the hardlink's shallower location. The same relative target can therefore resolve outside the extraction root after relocation.
- [GHSA-7r27-jhmm-vmp6 / CVE-2026-3087](https://github.com/advisories/GHSA-7r27-jhmm-vmp6) describes `shutil.unpack_archive()` accepting a ZIP member with a Windows drive-absolute path and extracting it outside the selected destination on Windows.
- [GHSA-gf2w-jqmq-fcm8 / CVE-2026-4360](https://github.com/advisories/GHSA-gf2w-jqmq-fcm8) describes `TarFile.extract()` failing to preserve `filter="data"` when processing a hardlink, allowing archive ownership metadata to survive a policy that should strip it.

The general bug-hunting heuristic is **validate the object in its final namespace and execution branch**. A check is not sufficient when later hardlink fallback, path parsing, or metadata restoration changes the member's location or semantics.

### Prerequisites and fixture

- Run affected and corrected Python builds in disposable Windows VMs or Linux user/mount namespaces as appropriate.
- Create random extraction and sibling-canary directories containing no sensitive data.
- Wrap or interpose filesystem operations so an outside-root `open`, `symlink`, `link`, `chown`, or replacement is recorded and denied.
- Capture the Python version, archive-member order/type/name/link target, extraction API, filter, platform path interpretation, effective UID, and canonical destination.

Build archives programmatically in the fixture rather than redistributing weaponized samples. For the hardlink-relocation case, use only a random sibling canary and stop at the denied outside-root operation.

| Case | Controlled change | Positive evidence |
| --- | --- | --- |
| ordinary file | in-root regular member | final canonical path remains below the extraction root |
| symlink baseline | in-root symlink whose target stays in root | archived and final-location resolutions both stay in root |
| hardlink baseline | hardlink to an earlier regular member | filter and canonical destination remain unchanged |
| relocated symlink fallback | hardlink references a deeper symlink that is recreated at a shallower name | archived-location resolution passes, final-location resolution reaches the sibling canary, and the sink is denied |
| Windows rooted path | ZIP member with a drive-qualified absolute name | parser records a destination outside the selected root without writing it |
| separator controls | equivalent relative names with `/`, `\\`, and mixed separators | platform-specific canonical destination table |
| ownership-filter branch | `TarFile.extract(..., filter="data")` on regular and hardlink members carrying synthetic UID/GID values | metadata application differs by member type on the affected build; corrected build strips it consistently |
| corrected build | replay byte-identical fixtures | each outside-root or forbidden-metadata action is rejected before its syscall |

Do not claim a generic `tarfile` escape from CVE-2026-4360: its demonstrated boundary is metadata-filter loss on the hardlink branch. Do not label a lexical drive path as exploitation until the Windows resolver or filesystem recorder proves the effective destination. For CVE-2026-11940, preserve both resolutions in evidence: the link target at its archived location and at the shallower location where fallback recreates it.

## GNU cpio absolute hard-link target matrix

[GHSA-rc3p-p5w3-fm9j / CVE-2026-66484](https://github.com/advisories/GHSA-rc3p-p5w3-fm9j) adds a distinct `cpio` case: in copy-in mode, `--no-absolute-filenames` normalizes an archive member name, but an absolute TAR hard-link target can reportedly reach `link()` without equivalent normalization. This is not ordinary `../` traversal and does not require a symlink chain. The policy-visible destination and the filesystem source selected for the hard link are separate authorities.

Use an unprivileged mount namespace containing only a temporary extraction root, one in-root source, and one random sibling canary. Interpose `link`/`linkat` so an outside-root source or destination is recorded and denied. Build the TAR fixture programmatically and do not redistribute it.

| Case | Archive metadata | Evidence to capture |
| --- | --- | --- |
| regular baseline | relative regular member | canonical write remains below extraction root |
| in-root hard link | relative destination and relative in-root target | source and destination both remain below root |
| destination control | absolute member name with a relative target | `--no-absolute-filenames` normalization and final destination |
| target-authority case | relative destination with an absolute target naming only the sibling canary | raw link target, normalized member name, final `link`/`linkat` source and destination; deny syscall |
| target spelling controls | repeated separators, dot segments, and relative equivalent | parser and canonical source decision table |
| corrected build | byte-identical archive and command | reject before any outside-root link syscall |

A bounded positive is **`--no-absolute-filenames` accepts the archive -> destination stays under the extraction root -> raw absolute hard-link target selects the synthetic sibling canary at the denied filesystem sink**. Do not create the link, point at host files, or claim an overwrite: this primitive links an existing outside object into the extraction tree unless another application behavior supplies additional impact.

## OpenCart extension-installer extraction boundary

[GHSA-3rx6-2g27-8gfq](https://github.com/advisories/GHSA-3rx6-2g27-8gfq) reports that OpenCart 4.2.0.0 installs uploaded `.ocmod.zip` extensions without proving that every extracted path remains under the extension staging root. This is a useful application-layer case because the archive is not merely unpacked: an authenticated extension workflow hands attacker-controlled member names to a server-side installer near the web application tree.

Use a disposable OpenCart lab with no production store, credentials, customer data, payment integration, or outbound network. Replace archive writes, moves, publication copies, and extension activation with record-and-deny sinks. Build fixtures programmatically and include only random marker files.

| Case | Member-name class | Required evidence |
| --- | --- | --- |
| baseline | ordinary relative file | canonical destination stays below the staging root |
| dot segments | single and repeated parent segments | decoded member, normalized path, canonical destination, denied outside-root write |
| encoded/name controls | mixed separators and any decoding performed before extraction | path at upload, ZIP parser, installer, and filesystem sink |
| directory entry | escaping directory followed by an ordinary child | whether child inherits an outside-root destination |
| symlink control | link entry plus later child where the ZIP stack supports links | final target resolution; deny link creation and write-through |
| lifecycle | install, validation failure, rollback, uninstall, and cleanup | every copy/move/delete root, not only initial extraction |
| corrected build | byte-identical marker archives | rejection occurs before any outside-root file operation |

A bounded positive is **authorized extension upload -> installer accepts the archive -> a member resolves outside the temporary extension root -> denied file sink records the synthetic sibling-canary destination**. Do not write a web shell, target the webroot, activate attacker code, overwrite configuration, or infer unauthenticated reachability. Record the exact role required to upload/install extensions and test rollback and uninstall separately: later lifecycle helpers can reintroduce the same path authority even after extraction is corrected.

## Archive creation and extraction need separate link checks

Two August 10 records cover opposite sides of the archive boundary:

- [GHSA-c2qp-v5vm-7vxf / CVE-2026-70622](https://github.com/advisories/GHSA-c2qp-v5vm-7vxf) reports that `tar-rs` `Builder::append_dir_all()` in versions 0.4.11 through 0.4.46 follows symlinks planted below an untrusted source directory and can include an outside-root file as an ordinary archive member.
- [GHSA-83x3-qgq9-rfcq / CVE-2026-19429](https://github.com/advisories/GHSA-83x3-qgq9-rfcq) reports that Jenkins `FilePath.untarFrom()` validates where a symlink is created but not where its target resolves, allowing a build-triggered extraction path to retain an outside-pointing symlink. The GitHub record is unreviewed; confirm the deployed Jenkins code path and behavior before making an impact claim.

The first is a **source-tree read boundary during archive creation**. The second is a **target-resolution and lifecycle boundary during extraction**. A safe extractor does not make an archive builder safe, and validating a symlink's destination name does not validate its target.

Use a disposable root containing an ordinary marker, an in-root symlink target, and a random sibling canary. Interpose file reads, link creation, and later opens so any sibling-canary operation is recorded and denied. Never point fixtures at Jenkins secrets, credentials, user configuration, source repositories, or host files.

| Case | Controlled fixture | Evidence to capture |
| --- | --- | --- |
| builder baseline | ordinary files below the source root | enumerated source path and emitted member type/name |
| builder in-root link | symlink resolving to an in-root marker | raw link, canonical read target, and whether the archive preserves or dereferences it |
| builder source escape | source-tree symlink resolving only to the sibling canary | `lstat`/`readlink`, canonical read target, denied read, and absence of canary bytes from the archive |
| extractor baseline | regular member and an in-root symlink | created object type plus canonical target |
| extractor target escape | symlink destination below the extraction root but target resolving to the sibling canary | raw target, final resolution, denied `symlink`/later open, and no outside read |
| Jenkins lifecycle | build request, extraction, cache reuse, console/report publication, and cleanup | required item permission, retained link identity, every later dereference sink, and authorization on each response |
| corrected builds | byte-identical tree/archive fixtures | outside-root read or link is rejected before the filesystem sink |

For `tar-rs`, a bounded positive is **privileged archiver accepts an untrusted directory -> planted link resolves outside the approved source root -> denied read sink observes the sibling canary as the effective source**. Do not require archive disclosure of real data.

For Jenkins, stop at **authorized low-privilege build trigger -> tar extraction accepts an outside-pointing link -> a later synthetic cache or publication read would dereference it at the denied sink**. Capture whether the link persists across builds, who can trigger the extraction, and which endpoint would return the resulting marker. Do not retrieve `master.key`, `hudson.util.Secret`, `credentials.xml`, user configuration, tokens, or any production console data. Do not repeat the advisory's claimed credential-decryption or code-execution chain.

## Python `unearth` traversal and symlink-composition follow-up

[GHSA-2fcv-9f95-p67v / CVE-2026-73030](https://github.com/advisories/GHSA-2fcv-9f95-p67v) reports that `unearth` through 0.18.2 checked archive destinations with an `is_within_directory` function that did not normalize paths before containment validation. The unreviewed record identifies both `../` member names and symlink composition as outside-root write paths; it points to commit `6c78164` as the fix. Confirm the exact package build and application call path before reporting.

Use a disposable Python environment with an empty extraction root, a random sibling canary directory, and patched file/link/rename sinks. Construct TAR fixtures locally with inert markers and compare:

| Case | Member layout | Evidence |
| --- | --- | --- |
| baseline | ordinary relative file | canonical destination remains in root |
| lexical traversal | parent segments and dot segments | raw name, normalized name, canonical destination, denied write |
| separator controls | `/`, `\\`, repeated, and mixed separators | platform-specific parser and filesystem decisions |
| symlink baseline | in-root link to an in-root marker | target remains confined |
| link composition | link below root points only to the sibling canary, followed by a child member | link target and final child destination are checked at the sink |
| ordering | child-before-link, link-before-child, duplicate replacement | final object identity and operation order |
| corrected build | byte-identical fixtures | rejection occurs before outside-root create/link/open |

A bounded positive is **archive member passes `is_within_directory` -> final normalized or link-resolved destination is the synthetic sibling canary -> denied filesystem sink records the operation**. Do not overwrite an existing file, target startup/configuration paths, create a persistent outside-pointing link, or infer package-install code execution without proving a separate consumer.

### Reporting skeleton

```text
Extractor/API and version:
Platform and path semantics:
Archive member order and types:
Requested policy/filter:
Archived location -> canonical target:
Final recreated location -> canonical target:
Filesystem or metadata sink observed:
Outside-root operation denied at:
Affected versus corrected result:
Impact demonstrated (path escape or metadata drift):
```

## aqua `mholt/archives` symlink-follow write follow-up

[GHSA-mf5c-hw34-4hpp / CVE-2026-55569](https://github.com/advisories/GHSA-mf5c-hw34-4hpp) reports that `aquaproj/aqua` extracts downloaded tool archives through `pkg/unarchive/archives.go` using `github.com/mholt/archives`. The handler creates symlink entries with `os.Symlink(f.LinkTarget, dstPath)` **without validating that the symlink target resolves inside the extraction destination**. A subsequent regular-file archive entry with the same path is opened with `OpenFile(dstPath, O_CREATE|O_WRONLY)`, which **follows the attacker-planted symlink**. A malicious or compromised aqua package / release asset can therefore write attacker-controlled bytes outside aqua's extraction directory, with the privileges of the user running aqua.

This is the "create-then-dereference" composition already covered above, instantiated in a Go tool-manager context:

| Case | Member layout | Evidence |
| --- | --- | --- |
| baseline | ordinary relative file | canonical destination stays in root |
| symlink outside root | link below extraction root points at a sibling canary | `os.Symlink` records the target; target escapes root |
| same-path dereference | a regular-file member with the symlink's path | `OpenFile(O_CREATE\|O_WRONLY)` follows the link to the sibling canary; denied sink records the outside-root write |
| corrected build | byte-identical fixtures | containment check rejects before `os.Symlink`/`OpenFile` |

Replayable validation: a disposable aqua root, a random sibling canary directory outside the extraction root, and a patched/denied `symlink`/`open`/`rename` sink. Build a local archive fixture with an inert marker file plus an out-of-root symlink followed by a same-path regular member. The bounded positive is **symlink entry passes containment → final `OpenFile` destination is the synthetic sibling canary → denied filesystem sink records the outside-root write**. Do not overwrite an existing file, target startup/configuration paths, plant a persistent outside-pointing link, or infer package-install code execution without proving a separate consumer.

## Junrar `LocalFolderExtractor` intermediate-mkdir escape (GHSA-89m4-43j5-vhhx)

[GHSA-89m4-43j5-vhhx](https://github.com/advisories/GHSA-89m4-43j5-vhhx) (published 2026-09-17T16:30Z) is the containment-check-granularity variant of the same family: `createFile()` validates only the **final canonical file path**, while `makeFile()` walks the entry's path segments calling `dir.mkdir()` for each intermediate directory **with no containment check**. A crafted RAR entry makes the final file resolve inside the destination while intermediate `mkdir()` calls create attacker-chosen directories outside the extraction root. Default impact is outside-root **directory creation**, not arbitrary content write.

Reusable check: extraction containment must cover **every filesystem side effect** — intermediate directory creation, symlink/hardlink creation, permission changes — not only the final file's canonical path. Audit any extractor by listing which operations validate containment versus which just execute; test with a lab RAR/zip fixture whose member path implies a sibling marker directory, and prove only that the outside-root directory creation attempt is recorded by a denied sink.

## References

- aqua `mholt/archives` symlink-follow write: https://github.com/advisories/GHSA-mf5c-hw34-4hpp
- GitHub Advisory example: `malcontent` symlink path traversal due to argument confusion + missing symlink validation (CVE-2026-24846)
- GNU tar `--one-top-level` hardlink boundary: https://github.com/advisories/GHSA-4f5j-wqjr-hx49
- GNU tar incremental restore TOCTOU boundary: https://github.com/advisories/GHSA-v7fx-gjvh-347c
- CPython hardlink-to-symlink relocation boundary: https://github.com/advisories/GHSA-9mc4-rqmq-h467
- CPython Windows drive-absolute ZIP boundary: https://github.com/advisories/GHSA-7r27-jhmm-vmp6
- CPython hardlink ownership-filter boundary: https://github.com/advisories/GHSA-gf2w-jqmq-fcm8
- GNU cpio absolute hard-link target boundary: https://github.com/advisories/GHSA-rc3p-p5w3-fm9j and https://cert.pl/en/posts/2026/08/CVE-2026-66484
- OpenCart extension-installer ZIP traversal: https://github.com/advisories/GHSA-3rx6-2g27-8gfq
- tar-rs source-tree symlink escape during archive creation: https://github.com/advisories/GHSA-c2qp-v5vm-7vxf
- Jenkins extraction symlink-target validation boundary: https://github.com/advisories/GHSA-83x3-qgq9-rfcq
- Python `unearth` traversal and symlink-composition boundary: https://github.com/advisories/GHSA-2fcv-9f95-p67v
