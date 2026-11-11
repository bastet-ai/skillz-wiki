---
title: PyPI account-compromise supply-chain simulation and detection
---

# PyPI account-compromise supply-chain simulation and detection

Use this workflow when authorizing a red-team supply-chain simulation, when auditing an organization's Python supply chain for prior compromise, or when designing detection for PyPI account-takeover campaigns. The pattern below was extracted from the June 2026 "Hades" campaign (Mini Shai-Hulud / Miasma lineage), which used a stolen long-lived PyPI API token to upload trojanized wheels directly to PyPI while the GitHub source repository remained clean.

## Durable pattern

The attacker's delivery chain has three observable stages that each create a separate detection and testing surface:

| Stage | Mechanism | Detection surface |
| --- | --- | --- |
| Wheel packaging | `*-setup.pth` file inside the wheel that Python executes at interpreter startup via `.pth` auto-run | `site-packages` inventory, unexpected `.pth` files, wheel metadata diff vs. GitHub source |
| Runtime bootstrap | `.pth` downloads and executes a JavaScript runtime (Bun) from an external URL | `~/.bun` directory, outbound HTTP from Python startup, process spawn at interpreter init |
| Credential harvesting | Obfuscated JS (`_index.js`) enumerates environment variables, `~/.pypirc`, `~/.npmrc`, `~/.aws`, SSH keys, and API tokens, then exfiltrates | File presence in home directory, outbound DNS/HTTP to attacker infrastructure, process parent = Python/Bun |

The key recon insight: **only the PyPI artifacts are affected.** The GitHub source, git tags, and all other distribution channels remain clean. This means a supply-chain audit that only checks the source repository will miss the compromise.

## Recon workflow

1. **Identify the target package and its PyPI account.** Determine whether the package was published under a single-maintainer account, a team account, or an organization. Check the PyPI JSON API (`https://pypi.org/pypi/<pkg>/json`) for publish timestamps, release count, and account changes.
2. **Diff the PyPI wheel against the GitHub source.** Download the wheel and extract it. Compare the file tree, `setup.py` / `pyproject.toml`, and any `.pth`, `.py`, or `.js` files against the corresponding git tag. Any file present in the wheel but absent from the git tag is a red flag.
3. **Inspect `.pth` files in `site-packages`.** Run:
   ```bash
   python3 -c "import site; [print(p) for p in site.getsitepackages()]" | \
   xargs -I{} find {} -maxdepth 1 -name '*.pth' -exec echo {} \; -exec cat {} \;
   ```
   Flag any `.pth` file whose content is not a standard `import` statement or `site.addsitedir()` call. A `.pth` that makes an HTTP request, downloads a binary, or references a non-standard module path is an indicator of compromise.
4. **Check for external runtime downloads.** Look for:
   - `~/.bun`, `~/.deno`, `~/.cargo/bin/rustup` (if unexpected)
   - `/tmp` or `~/.cache` for recently created executables
   - `lsof` / `netstat` for outbound connections from Python or Bun processes
5. **Review PyPI account security.** If the assessment scope includes the target's PyPI account, check:
   - Active API tokens and their last-used timestamps
   - Account 2FA status
   - Recent password/email changes
   - Whether the token was long-lived (pre-2024 PyPI tokens had no expiry)

## Red-team simulation design

For an authorized supply-chain simulation, the goal is to demonstrate that an organization's Python environment would be compromised by a trojanized wheel without actually exfiltrating real credentials.

### Inert payload canaries

Build a trojanized wheel fixture with the same structural shape as the Hades pattern but with inert, non-executing payloads:

```python
# setup.py (trojanized wheel fixture)
from setuptools import setup

setup(
    name="skillz-canary-pkg",
    version="0.1.0",
    # The .pth file is the delivery mechanism. In the fixture,
    # it references a local marker instead of downloading a runtime.
    package_data={
        "skillz_canary_pkg": ["skillz-setup.pth"],
    },
)
```

The `skillz-setup.pth` fixture should contain:

```text
# SKILLZ_SUPPLY_CHAIN_CANARY: This file would normally download a JS runtime.
# In this simulation, it creates a marker file instead.
import os; open(os.path.expanduser("~/.skillz-canary-pth-executed.txt"), "w").write("MARKER")
```

### Validation steps

1. Build the trojanized wheel: `python3 -m build --wheel`
2. Install it in an isolated virtual environment: `pip install ./skillz_canary_pkg-0.1.0-py3-none-any.whl`
3. Start a fresh Python interpreter in the venv and confirm `~/.skillz-canary-pth-executed.txt` was created.
4. Record the `.pth` file's path, its content, and the marker file's mtime.
5. Negative control: install the clean GitHub-source version and confirm no `.pth` file appears.

### Evidence to capture

- Wheel file hash (SHA-256) and file tree listing.
- The `.pth` file content (redacted of any real attacker infrastructure).
- Marker file path, creation time, and content.
- Process tree showing Python → marker-file creation (in the inert fixture).
- A before/after table of `site-packages` contents.

### Safety constraints

- Do not download or execute any real external runtime in the simulation.
- Do not point the fixture's `.pth` at a real credential store, real PyPI, or real cloud metadata.
- Do not use the fixture against a shared or production Python environment.
- Do not capture real `~/.aws`, `~/.npmrc`, `~/.pypirc`, or SSH keys in any simulation output.
- Keep the inert marker to a single file in the home directory; do not create or modify shell startup files.

## Bug-hunting heuristic

For a bug bounty or internal assessment of an organization's Python supply chain:

1. Enumerate all `site-packages` directories in scope (production, CI, dev).
2. Flag any `.pth` file that contains more than a single `import` or `site.addsitedir()` line.
3. Cross-reference the package that owns the `.pth` against its PyPI release history. A `.pth` file that was added in a specific release (check the wheel's `RECORD` file) is a strong signal of targeted compromise.
4. Report as: **unexpected `.pth` auto-execution file in `site-packages` -> Python interpreter startup -> external runtime download -> credential enumeration surface**. The impact is host-level credential exposure for any process that starts Python in the affected environment.

## Sources

- GitHub Security Advisory: [GHSA-93qj-5q5v-3c2h](https://github.com/advisories/GHSA-93qj-5q5v-3c2h), Trojanized `pantheon-agents` 0.6.1 and 0.6.2 on PyPI
- PantheonOS security advisory: https://github.com/aristoteleo/PantheonOS/security/advisories/GHSA-93qj-5q5v-3c2h
- PyPI JSON API for package metadata: https://pypi.org/pypi/pantheon-agents/json
