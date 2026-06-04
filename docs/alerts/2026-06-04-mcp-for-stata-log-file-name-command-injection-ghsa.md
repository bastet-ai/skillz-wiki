# MCP-for-Stata `log_file_name` command-injection boundary

## Operator value

GitHub advisory [GHSA-4p62-hqp5-g644 / CVE-2026-47708](https://github.com/advisories/GHSA-4p62-hqp5-g644) describes command injection in `stata-mcp` before `1.17.3`: the user-controlled `log_file_name` parameter for the `stata_do` MCP tool and `stata-mcp tool do` CLI is embedded into a generated Stata command string without validation.

For authorized testing, treat this as an agent-tool wrapper boundary. The do-file guard scans Stata script content, but wrapper parameters can still alter the command stream that the tool sends to Stata.

## Affected surface

- Product/package: MCP-for-Stata / `stata-mcp`
- Ecosystem: Python / pip
- Affected versions: `< 1.17.3`
- Fixed version: `1.17.3`
- Required position: ability to influence MCP tool arguments or CLI parameters for a host that has Stata and `stata-mcp` installed
- Risk pattern: tool wrappers that validate primary script/input content but interpolate auxiliary parameters into an interpreter command string

## Recon workflow

1. Confirm the target is in scope and that agent-tool testing is explicitly authorized.
2. Inventory MCP/Stata usage from authorized evidence:
   - MCP server configs that expose a Stata tool;
   - Python dependency manifests containing `stata-mcp`;
   - agent harness logs or tool catalogs showing `stata_do`;
   - CLI usage of `stata-mcp tool do` in notebooks, CI jobs, or analyst workstations.
3. Verify the installed version from a lab replica or approved shell on the assessed host:

   ```bash
   python -m pip show stata-mcp
   python -m pip freeze | grep -i '^stata-mcp=='
   ```

4. Identify who can set `log_file_name`. Prioritize multi-user agent workbenches, shared MCP servers, delegated notebook execution, and any workflow where untrusted prompts or tickets can become tool arguments.
5. Review adjacent wrapper parameters too. This advisory is about `log_file_name`, but the durable lesson is that every parameter embedded into generated Stata commands must be treated as code-adjacent input.

## Safe validation pattern

Use a lab clone or a disposable test account. The goal is to prove command-stream injection with a harmless canary file, not to run destructive Stata or shell commands.

1. Prepare an inert do-file:

   ```stata
   display "stata-mcp boundary canary"
   ```

2. Send a benign baseline through the same execution path used by the target workflow:

   ```bash
   stata-mcp tool do ./canary.do --log-file-name baseline_canary
   ```

   Expected contained result: the run creates a normal Stata log named from `baseline_canary`, with no shell side effects.

3. In a lab only, submit a `log_file_name` canary that attempts to break the quoted Stata `log using` command and write a fixed marker to a temporary path:

   ```bash
   stata-mcp tool do ./canary.do \
     --log-file-name "'; shell printf stata_mcp_log_boundary_canary >/tmp/stata_mcp_log_boundary_canary; '"
   ```

4. Record the outcome:
   - **Contained:** the wrapper rejects the name, escapes it, or writes only a normal log file under the expected log directory.
   - **Vulnerable:** the Stata command stream executes the injected `shell` statement and creates the marker file.

5. Remove only the inert canary artifact you created:

   ```bash
   rm -f /tmp/stata_mcp_log_boundary_canary
   ```

## MCP harness probe

When testing through an MCP client, keep the same proof bounded to an inert marker. The argument shape from the advisory is:

```json
{
  "dofile_path": "./canary.do",
  "log_file_name": "'; shell printf stata_mcp_log_boundary_canary >/tmp/stata_mcp_log_boundary_canary; '"
}
```

A valid finding shows that an MCP caller can influence `log_file_name`, that the target runs a vulnerable `stata-mcp` version, and that the generated Stata command stream executes an injected command despite any do-file content guard.

## Path-traversal companion check

The advisory also notes that `log_file_name` can be used to construct log paths outside the intended log directory. Validate this separately and non-destructively:

```bash
stata-mcp tool do ./canary.do --log-file-name "../stata_mcp_path_boundary_canary"
```

Capture whether the log path resolves outside the configured log directory. Do not overwrite existing files; use unique canary names and inspect only paths created for the test.

## Evidence to capture

- `stata-mcp` version and how it was verified.
- The exact tool path tested: MCP client call, server config, CLI, notebook job, or CI task.
- Minimal benign and canary request/response pairs.
- The generated log path or command output proving whether the wrapper escaped, rejected, or executed the canary.
- Confirmation that the test used inert files and did not access or modify sensitive datasets.

## Report framing

Frame this as a tool-wrapper command-injection boundary failure: policy validation covered do-file content, but an auxiliary filename parameter was interpolated into a Stata command string. Impact depends on which identities can call the MCP tool and what OS privileges the Stata process has on the host.

## Sources

- GitHub Advisory Database: [GHSA-4p62-hqp5-g644 / CVE-2026-47708](https://github.com/advisories/GHSA-4p62-hqp5-g644)
- Project advisory: [SepineTam/stata-mcp GHSA-4p62-hqp5-g644](https://github.com/SepineTam/stata-mcp/security/advisories/GHSA-4p62-hqp5-g644)
- Issue reference: [SepineTam/mcp-for-stata issue #74](https://github.com/SepineTam/mcp-for-stata/issues/74)
- Fix commit: [`e6f945941ae0c7cf5e74a428e0b3dc82b396382f`](https://github.com/SepineTam/stata-mcp/commit/e6f945941ae0c7cf5e74a428e0b3dc82b396382f)
