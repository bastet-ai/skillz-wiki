# 2026-02-06 — Semantic Kernel (SessionsPythonPlugin) arbitrary file write (GHSA-2ww3-72rp-wpp4)

GitHub advisory: <https://github.com/advisories/GHSA-2ww3-72rp-wpp4>

## Summary

A critical **arbitrary file write** issue was disclosed in Microsoft’s Semantic Kernel .NET SDK, in/around the `SessionsPythonPlugin`.

If an attacker can influence agent function-calling arguments (or your app accepts untrusted tool/function call inputs), they may be able to write files to attacker-chosen paths on the host.

Arbitrary file write is frequently a stepping stone to:

- **Remote Code Execution** (dropping/overwriting scripts, configs, web assets)
- **Credential theft** (overwriting logs/configs to exfiltrate secrets)
- **Persistence** (placing startup items, scheduled tasks, plugin drops)

## Who is at risk

Higher risk when:

- The app exposes agent/tool invocation to untrusted users (directly or indirectly).
- The app runs with filesystem write privileges in sensitive directories.
- The app runs on servers with multi-tenant data or shared workspaces.

## Mitigation

1. **Upgrade**
   - Update to patched versions per advisory (or later).
2. **Add strict allowlists for file paths** (defense-in-depth)
   - Only allow writes under a dedicated directory (e.g., `/var/lib/app/uploads/`), and enforce containment.
   - Reject `..`, absolute paths, UNC paths, and symlink escapes.
3. **Constrain tool/function calling**
   - If your agent can call `UploadFileAsync` / `DownloadFileAsync` (or similar), validate arguments centrally.
   - Prefer “capability-based” tools: explicit operations with narrow scopes, not raw filesystem paths.
4. **Reduce blast radius**
   - Run the service as a dedicated OS user.
   - Remove write permissions outside the dedicated workspace.

## Detection / hunt

- File integrity monitoring: unexpected file creation/modification in:
  - application directories
  - web roots
  - config directories
  - temp directories used by the agent
- App logs: tool/function call requests that include suspicious `localFilePath` values.
- OS telemetry: new scheduled tasks, startup items, or unexpected binaries/scripts appearing on disk.