# `launch-editor` Windows command-injection boundary

**Sources:** [GHSA-c27g-q93r-2cwf](https://github.com/advisories/GHSA-c27g-q93r-2cwf), [Vite `launch-editor` advisory](https://github.com/vitejs/launch-editor/security/advisories/GHSA-c27g-q93r-2cwf), [patch commit](https://github.com/vitejs/launch-editor/commit/971291e8a6a91226e1616c5c0ec85423d2d50a5e)  
**Affected packages:** npm `launch-editor` `<= 2.8.2`; npm `vite` `<= 5.4.8` through the affected helper. Patched in `launch-editor` `2.9.0` and `vite` `5.4.9`.  
**Operator value:** source-assisted validation for development servers or tooling endpoints that pass attacker-controlled file paths into editor-launch helpers on Windows.

## Why this matters

GHSA-c27g-q93r-2cwf documents command injection in `launch-editor` on Windows. The vulnerable boundary is the `file` argument passed into `launchEditor`: when a filename containing shell metacharacters reaches the helper, the editor launch path can execute attacker-controlled commands.

The durable testing lesson is: **developer-convenience routes are application attack surface when they convert request-controlled file paths into local editor, shell, or process-spawn actions.** During authorized testing, treat open-in-editor links, stack trace source links, source-map viewers, and dev-server overlays as path-to-process boundaries, especially on Windows workstations.

## Recon targets

Prioritize environments where all of these are true:

1. the target is an explicitly authorized dev, staging, preview, or internal tooling environment;
2. a reachable endpoint or UI action launches a local editor for a supplied file path;
3. the host executing the helper is Windows;
4. the resolved dependency includes `launch-editor` `<= 2.8.2` or Vite `<= 5.4.8`.

Source-review starting points:

```bash
# Dependency reachability.
grep -R '"launch-editor"\|"vite"' -n package.json package-lock.json pnpm-lock.yaml yarn.lock 2>/dev/null
npm ls launch-editor vite 2>/dev/null
pnpm why launch-editor vite 2>/dev/null
yarn why launch-editor 2>/dev/null

# Editor-launch and dev-overlay call sites.
grep -R "launchEditor\|openInEditor\|__open-in-editor\|open-in-editor\|editor" -n src server scripts config . 2>/dev/null
```

High-signal application patterns:

- dev servers exposed beyond localhost for pair debugging, preview environments, or internal demos;
- stack traces or error overlays with clickable source-file links;
- custom routes that accept `file`, `path`, `filename`, `line`, or `column` and open an editor;
- tooling that downloads, creates, or references predictable filenames before opening them;
- Windows-based developer workstations, CI agents, or remote dev boxes running the affected helper.

## Safe validation workflow

Use a local lab, a disposable Windows VM, or an explicitly authorized internal dev host. Do not attempt command execution on a developer's personal workstation or any system outside the agreed test scope.

### 1. Confirm the vulnerable dependency and reachable helper

```bash
npm ls launch-editor vite
node -e "for (const p of ['launch-editor/package.json','vite/package.json']) { try { const x=require(p); console.log(p, x.version) } catch(e) {} }"
```

A finding maps to this advisory only when the vulnerable helper is present and a request-controlled path reaches the editor-launch call. A dependency-only finding is weaker than evidence showing the path-to-helper boundary.

### 2. Map the path-to-process boundary

Before sending probes, document exactly how the path is built:

| Boundary | Question to answer |
| --- | --- |
| Input source | Which route, query parameter, websocket message, or UI action supplies the path? |
| Path normalization | Are absolute paths, drive letters, UNC paths, spaces, quotes, or metacharacters filtered? |
| File existence | Must the file already exist, or can the workflow create/download it first? |
| Host OS | Is the process that launches the editor running on Windows? |
| Sink | Does the value reach `launchEditor`, `child_process`, an editor CLI, or another process-spawn wrapper? |

### 3. Use inert canaries before any command proof

Start with non-executing metacharacter canaries that prove parsing risk without running a payload:

```text
canary file names for lab use only:
normal-file.js
space in name.js
quote"canary.js
ampersand&canary.js
pipe|canary.js
caret^canary.js
percent%25canary.js
```

Evidence worth collecting:

- the exact redacted request that supplies the filename;
- application logs showing the path value reaches the editor-launch branch;
- a local lab trace showing the affected version mishandles the canary and the patched version rejects or safely quotes it;
- a dependency tree tying the running service to `launch-editor` `<= 2.8.2` or Vite `<= 5.4.8`.

Only move beyond inert canaries when the program owner has explicitly approved command-execution validation, and keep the proof non-destructive and local to the test host.

### 4. Controls to avoid false positives

| Control | Expected result |
| --- | --- |
| Same request against `launch-editor` `2.9.0` or later | Filename is safely handled or rejected |
| Same request on non-Windows host | Does not exercise this advisory's Windows command-injection path |
| Filename without metacharacters | Opens or attempts to open only the intended file |
| Invalid or nonexistent file when existence is required | Rejected before editor launch |
| Route inaccessible without dev tooling enabled | Report exposure only within the authorized dev/staging scope |

If the route launches arbitrary local paths even after the package is patched, report that as a separate insecure dev-tool exposure or local file/open redirect problem rather than overfitting to GHSA-c27g-q93r-2cwf.

## Reporting heuristic

Frame the issue around a developer-tool path-to-process boundary:

- **Expected boundary:** request-controlled filenames must be normalized, quoted, and constrained before any editor or process-spawn helper runs.
- **Observed bypass:** a crafted filename reaches vulnerable `launch-editor` behavior on Windows through an exposed dev-server/editor-launch path.
- **Impact:** command execution in the context of the Windows user running the development server or tooling process.
- **Evidence:** dependency version, reachable route/call site, redacted request, inert canary behavior, OS context, and patched-version control.

## Scope and safety notes

- Keep testing limited to authorized dev/staging/lab hosts; do not target personal workstations.
- Avoid destructive payloads and avoid collecting local files, secrets, shell history, or editor state.
- Prefer source review plus inert canaries; command execution proof requires explicit approval.
- Do not report production impact unless the affected dev-tool route is actually exposed in the production attack surface.
