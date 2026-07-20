# Composer repository metadata and package-install boundary checks

Sources: hourly offensive-security scan, 2026-07-20 GitHub Security Advisory feed. Primary entries: [GHSA-499r-g7pc-vmp9](https://github.com/advisories/GHSA-499r-g7pc-vmp9), [GHSA-gqw4-4w2p-838q](https://github.com/advisories/GHSA-gqw4-4w2p-838q), and [GHSA-wg36-wvj6-r67p](https://github.com/advisories/GHSA-wg36-wvj6-r67p). The package-validation change is visible in Composer commits [`502c6c4`](https://github.com/composer/composer/commit/502c6c4f699802d9cf464728b3e8a95674f919a0) and [`c50b1ef`](https://github.com/composer/composer/commit/c50b1efd13ebd73f6dca19b31424c5a02bf93cc1).

These advisories expose three reusable PHP supply-chain boundaries: dependency resolution can accept a transitive package name that later becomes a filesystem path; repository-supplied source metadata can cross into a Perforce command; and a root project's Perforce repository configuration can reach the same command builder even when Perforce is absent. For operators, the durable lesson is to trace package metadata from every configured repository through resolution, lockfile generation, install paths, and VCS process arguments—not merely to inspect package scripts.

!!! warning "Authorized validation only"
    Use a disposable container or VM, a synthetic Composer project, an owned local package repository, fake Perforce metadata, and marker files under a dedicated temporary root. Disable network access after fixtures are staged. Never point the harness at a real developer home directory, package mirror, CI runner, SSH configuration, shell startup file, cron directory, or production repository credentials.

## What changed

| Advisory | Affected path | Preconditions | Operator value |
| --- | --- | --- | --- |
| [GHSA-499r-g7pc-vmp9](https://github.com/advisories/GHSA-499r-g7pc-vmp9) / CVE-2026-59948 | Resolved transitive package name -> install path and file write | Composer 1.x, `>=2.3.0,<2.10.2`, or the 2.2 LTS line before `2.2.29`; a malicious or compromised third-party repository returns an invalid package name | Test whether repository metadata escapes `vendor/` or the project before package code is expected to run. Packagist.org and Private Packagist validate names and are not the advisory's attack source. |
| [GHSA-gqw4-4w2p-838q](https://github.com/advisories/GHSA-gqw4-4w2p-838q) / CVE-2026-40261 | Repository package metadata `source.reference` or Perforce source URL -> shell-built `p4` command | Composer 1.x, `>=2.3.0,<2.9.6`, or the 2.2 LTS line before `2.2.27`; dependency installed from source, including dev-version defaults or `--prefer-source` | Validate command/argument boundaries reached through transitive metadata from a compromised or malicious Composer repository. Perforce need not be installed for the command attempt to occur. |
| [GHSA-wg36-wvj6-r67p](https://github.com/advisories/GHSA-wg36-wvj6-r67p) / CVE-2026-40176 | Root `composer.json` Perforce port, user, or client values -> shell-built command | Same affected Composer ranges; operator runs Composer in an untrusted project or with attacker-controlled global Composer config | Review cloned PHP projects as executable build input even when their declared dependencies do not visibly use Perforce. Dependency `composer.json` files cannot introduce repository definitions through this route. |

The July file-write fix adds a security-sensitive validation pass after dependency resolution and before resolved packages are written to `composer.lock` or installed. It rejects structurally invalid package names, source/dist URLs or references beginning with `-`, and package `bin` paths containing `..` segments. This placement matters: validating only the root manifest or the repository's first JSON representation misses metadata loaded through a less strict resolver path.

## Preconditions and inputs

Collect these before testing:

- exact Composer version and whether the binary is the normal or 2.2 LTS line;
- `composer.json`, `composer.lock`, and global Composer configuration from the disposable fixture;
- the effective repository list, including `type: composer`, VCS, artifact, path, and proxy/mirror endpoints;
- install preference (`dist`, `source`, or `auto`) and whether dev versions are selected;
- the process owner, working directory, `vendor-dir`, `bin-dir`, Composer home/cache paths, and container mounts;
- an empty dedicated test root with an outside-`vendor` canary path that is still inside that root;
- patched Composer releases for negative controls: `2.10.2` or `2.2.29` for the resolved-package validation issue, and `2.9.6` or `2.2.27` for the Perforce issues.

Do not infer exploitability from a version banner alone. The package-name issue needs an untrusted third-party repository in the dependency graph. The repository-metadata Perforce issue needs a source install path. The root-config issue needs an untrusted project or global Composer config.

## Repository and resolution recon

Run these only in a copied project or assessment workspace. Redact credentials from all captured output.

```bash
composer --version
composer config --list --source
composer repo list
composer show --locked --tree
composer install --dry-run --no-scripts --no-plugins --no-interaction -vvv
```

Review manifest and lockfile metadata without executing plugins or scripts:

```bash
python3 - <<'PY'
import json
from pathlib import Path

for filename in ("composer.json", "composer.lock"):
    path = Path(filename)
    if not path.exists():
        continue
    data = json.loads(path.read_text())
    print(f"## {filename}")
    if filename == "composer.json":
        print("repositories:", json.dumps(data.get("repositories", []), indent=2))
    else:
        for section in ("packages", "packages-dev"):
            for package in data.get(section, []):
                print(json.dumps({
                    "section": section,
                    "name": package.get("name"),
                    "source": package.get("source"),
                    "dist": package.get("dist"),
                    "bin": package.get("bin"),
                }, sort_keys=True))
PY
```

Flag for manual review:

- package names that do not have one ordinary `vendor/package` separator or that contain path/option-like syntax;
- `source.type: perforce`, unusual source references, or source/dist fields that begin with `-` after leading whitespace;
- package `bin` entries containing a `..` path component with either slash style;
- non-Packagist repositories that can supply transitive metadata;
- a lockfile generated by a different trust environment than the install runner;
- `preferred-install: source`, `--prefer-source`, or dev dependencies likely to select source installs.

This static pass is triage, not proof. A report needs the resolver/install decision and a vulnerable-versus-patched control.

## Replayable validation workflow

### 1. Build a contained fixture

1. Create a disposable container or VM and mount only an empty test directory. Set `HOME`, `COMPOSER_HOME`, cache, project, `vendor-dir`, and `bin-dir` beneath that directory.
2. Stage two Composer binaries: one affected release matching the target branch and one fixed release. Record their hashes.
3. Serve a minimal local Composer repository from loopback. Use only synthetic package names, archives, and references; block all non-loopback egress.
4. Place an unmistakable canary path outside `vendor/` but inside the disposable test root. Do not use a startup file, key file, cron path, or any file that another process consumes.
5. Snapshot the test root before each run and execute with plugins and scripts disabled so package metadata is isolated from intentional package code execution.

```bash
export LAB_ROOT="$(pwd)/composer-boundary-lab"
export HOME="$LAB_ROOT/home"
export COMPOSER_HOME="$LAB_ROOT/composer-home"
mkdir -p "$HOME" "$COMPOSER_HOME" "$LAB_ROOT/project" "$LAB_ROOT/outside-vendor"
find "$LAB_ROOT" -xdev -printf '%P\t%y\t%s\n' | sort > "$LAB_ROOT/before.tsv"
```

### 2. Resolved package-name to filesystem check

1. Make the root project require a normal synthetic package from the owned repository.
2. Have that package depend transitively on a fixture whose repository metadata uses a deliberately invalid, path-shaped package name targeting only the `outside-vendor` canary area.
3. Run the affected Composer in the isolated root with `--no-plugins --no-scripts --no-interaction`. Capture verbose resolution output, `composer.lock`, and a filesystem diff.
4. Repeat from a clean snapshot with Composer `2.10.2`/`2.2.29` or later. The fixed control should abort during dependency resolution with a security error before writing the lockfile or installing the invalid package.
5. Stop once an outside-`vendor` marker appears. Do not target files outside `LAB_ROOT` and do not convert the primitive into persistence.

```bash
(
  cd "$LAB_ROOT/project"
  /path/to/affected/composer install --no-plugins --no-scripts --no-interaction -vvv
) 2>&1 | tee "$LAB_ROOT/affected-install.log"
find "$LAB_ROOT" -xdev -printf '%P\t%y\t%s\n' | sort > "$LAB_ROOT/after.tsv"
diff -u "$LAB_ROOT/before.tsv" "$LAB_ROOT/after.tsv" || true
```

Report this as **third-party repository metadata -> invalid transitive package name survives resolution -> controlled write outside `vendor/`**. Include repository provenance and explain that this is a supply-chain precondition, not an unauthenticated remote attack on Composer.

### 3. Repository-supplied Perforce metadata check

1. Use the loopback repository to return a synthetic package with `source.type: perforce` and a marker-only source URL/reference designed to reveal argument or shell interpretation.
2. Select the source path explicitly with `--prefer-source`, or document why a dev-version install selects it by default.
3. Replace `p4` in the disposable `PATH` with an inert argv recorder. Also monitor process execution so the test distinguishes safe argv passing from a shell interpreting metadata. The recorder must only serialize its argument vector beneath `LAB_ROOT` and exit.
4. Compare affected Composer with `2.9.6`/`2.2.27` or later. Record whether the fixed release rejects the metadata before process launch.
5. Do not embed a shell command, callback, or credential read. An argument log plus a fixed-version rejection is enough to establish the boundary.

Report this as **untrusted repository `source` metadata -> Perforce command construction -> shell/argument interpretation before dependency code execution**. State whether source installation was explicit or selected by Composer.

### 4. Root-project Perforce configuration check

1. Create a separate synthetic root `composer.json` containing an owned Perforce repository fixture. Keep every dependency package normal.
2. Put one marker token at a time in the Perforce port, user, and client fields and use the same inert process recorder.
3. Run Composer commands that load the root repository configuration. Test even when no real `p4` binary is installed, because the vulnerable command construction can be reached before Composer proves Perforce is usable.
4. Repeat against patched Composer and with the Perforce repository removed as negative controls.
5. Attribute this route correctly: repository declarations come from the root project or global Composer config, not from a transitive dependency manifest.

Report this as **untrusted root project/global Composer config -> Perforce connection field -> command builder**. The practical recon signal is a cloned PHP project that declares an unexpected Perforce repository, even if the dependency list does not appear Perforce-related.

## Evidence to preserve

- Composer version output and hashes for affected/fixed binaries;
- redacted effective repository configuration and source/dist install preference;
- synthetic repository metadata and dependency graph showing direct versus transitive control;
- pre/post filesystem manifests restricted to the disposable test root;
- inert process argv records and process-execution traces;
- affected and fixed exit codes, security errors, and whether `composer.lock` was created or changed;
- confirmation that plugins, scripts, network egress, and host mounts were disabled.

A strong proof is a decision table:

| Case | Repository trust | Install mode | Expected affected result | Expected fixed result |
| --- | --- | --- | --- | --- |
| Normal `vendor/package` | owned fixture | dist | install under `vendor/` | same |
| Invalid transitive package name | owned malicious fixture | dist | outside-`vendor` canary write may occur | resolver aborts before lock/install |
| Perforce source reference | owned malicious fixture | source | metadata reaches unsafe command construction | metadata rejected or safely handled |
| Root Perforce connection field | untrusted synthetic project | config load/source path | field reaches unsafe command construction | field cannot trigger shell interpretation |

## Reporting notes

- Lead with the failed binding: repository identity and resolved package name were not bound to a safe install path, or metadata was not kept as data when building the VCS process invocation.
- Separate the three attacker positions: malicious third-party repository, malicious transitive package metadata, and untrusted root project/global config.
- Explicitly record `dist` versus `source`; the transitive Perforce reference path is not proven by a dist-only install.
- Do not claim that Packagist.org or Private Packagist can supply the invalid-name metadata described by GHSA-499r-g7pc-vmp9.
- Do not call the issues remotely exploitable against Composer itself. They execute during a user or automation-initiated install/update under specific supply-chain or project-trust preconditions.
- Redact repository credentials, bearer tokens, private package names, cache paths, developer usernames, and CI topology.
