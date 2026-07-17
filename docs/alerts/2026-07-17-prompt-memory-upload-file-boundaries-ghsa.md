# Prompt loader, MCP memory, and upload filename boundary checks

Sources: hourly offensive-security scan, 2026-07-17 GitHub Security Advisory updates. Primary entries: [GHSA-c4gh-rv8h-q9vw](https://github.com/advisories/GHSA-c4gh-rv8h-q9vw), [GHSA-wxhm-2mq7-7697](https://github.com/advisories/GHSA-wxhm-2mq7-7697), [GHSA-f7wf-v2vw-mpcx](https://github.com/advisories/GHSA-f7wf-v2vw-mpcx), and [GHSA-937x-gpqr-72gg](https://github.com/advisories/GHSA-937x-gpqr-72gg).

This batch is durable for operators because each advisory turns a familiar feature into an assessment pattern: prompt bundles parsed as code or file-read instructions, MCP memory import tools reading host files on behalf of a connected client, and upload helpers that validate one filename casing path but save another.

!!! warning "Authorized validation only"
    Use disposable prompt bundles, lab MCP servers, fake memory exports, temp upload roots, and harmless marker files. Never read production secrets, real user memory sessions, notebooks, SSH keys, `.env` files, service-account JSON, customer uploads, or web-executable shells.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-c4gh-rv8h-q9vw](https://github.com/advisories/GHSA-c4gh-rv8h-q9vw) / CVE-2026-53597 | `@prompty/core` TypeScript loader | `.prompty` frontmatter was parsed with `gray-matter` executable JavaScript engines enabled, so a `---js` frontmatter block could run in the host Node.js process during prompt loading | Treat prompt files and prompt marketplaces as executable supply-chain inputs, not inert text. |
| [GHSA-wxhm-2mq7-7697](https://github.com/advisories/GHSA-wxhm-2mq7-7697) / CVE-2026-53598 | Prompty loaders across PyPI, npm, crates.io, and NuGet | `${file:...}` frontmatter expansion accepted traversal, absolute paths, and symlink escapes instead of confining reads to the prompt bundle or explicit allow roots | Test AI prompt loaders for local-file disclosure when users can upload, select, or import prompt packages. |
| [GHSA-f7wf-v2vw-mpcx](https://github.com/advisories/GHSA-f7wf-v2vw-mpcx) / CVE-2026-54561 | `mcp-memory-keeper` `context_import` | Caller-controlled `filePath` reached `fs.readFileSync`; valid JSON could be imported and retrieved, while invalid JSON leaked leading bytes in parse errors | Validate MCP tools that bridge LLM/tool arguments to developer-workstation filesystems. |
| [GHSA-937x-gpqr-72gg](https://github.com/advisories/GHSA-937x-gpqr-72gg) / CVE-2026-54567 | Flask-Reuploaded `UploadSet.save()` name override | The default path lowercased extensions before denylist checks, but the caller-supplied `name` override revalidated a case-preserving extension, leaving a denylist bypass variant after CVE-2026-27641 | Probe upload helper APIs for validator/storage asymmetry, especially when applications override saved filenames. |

## Replayable validation boundaries

### Prompt loader execution checks

1. Create a disposable project that pins only the affected prerelease Prompty runtime being assessed.
2. Build a minimal `.prompty` fixture with an inert JavaScript frontmatter marker that writes only to a temp file inside the lab workspace or increments a local in-memory flag.
3. Load the prompt through the same application path used for user-submitted prompt bundles, marketplace prompts, repository prompts, or CI prompt tests.
4. Positive evidence is marker execution during parse/load before any model call or explicit tool invocation.
5. Negative controls should show fixed runtimes rejecting `js`/`javascript` frontmatter and accepting normal YAML frontmatter.

Report this as **untrusted prompt file -> executable frontmatter parser -> host process code execution during prompt load**. Include the package/version, loader path, sanitized fixture, marker output path, and fixed-version rejection behavior.

### Prompt file-reference read checks

1. Keep all proof files synthetic: a canary outside the prompt directory, a canary inside the prompt directory, and, if needed, a symlink that points to a synthetic outside file.
2. Add `${file:...}` references for normal relative paths, `..` traversal, absolute paths, and symlink escapes.
3. Load the prompt through each relevant runtime under test: Python, TypeScript, Rust, or .NET.
4. Positive evidence is the outside canary appearing in rendered prompt data, logs, API output, or error output.
5. Negative controls should show canonicalization to an allowed root, rejection of absolute/traversal targets, and explicit opt-in roots for shared prompt assets.

Report this as **prompt frontmatter file reference -> path resolution outside prompt root -> local file disclosure**. Do not use `/etc/passwd`, real home directories, cloud config, or application source as proof.

### MCP memory import file-read checks

1. Run `mcp-memory-keeper` in a lab with a disposable memory store and no real workspace secrets.
2. Prepare one synthetic valid JSON file outside the memory/export directory and one synthetic non-JSON file outside that directory.
3. Invoke `context_import` through an MCP client with `filePath` values for in-scope imports, `../` traversal, and absolute paths to the synthetic files.
4. Positive evidence can be either full import/retrieval of the JSON canary through `context_get`/`context_export`, or a returned parse error that includes bytes from the synthetic non-JSON canary.
5. Negative controls should show path confinement, extension/content checks, redacted parse errors, and caller/session binding for imported memory.

Report this as **MCP tool argument -> host filesystem read -> memory/session disclosure or parse-error byte leak**. Keep evidence to marker files and redact local paths that reveal operator workstation details.

### Upload filename case-asymmetry checks

1. Use a throwaway Flask app with a temp upload directory and a harmless dangerous-looking extension marker such as `marker.PHP` containing inert text.
2. Exercise both flows: the default save path and the application path that passes a caller-controlled or partially caller-controlled `name` override to `UploadSet.save()`.
3. Compare validation decisions and the final stored basename/extension for mixed-case variants.
4. Positive evidence is the default path rejecting/lowercasing while the name-override path accepts a case-preserving extension that the denylist should have blocked.
5. Negative controls should show the same normalized extension being checked for both the submitted file and the overridden storage name.

Report this as **upload filename/name override -> inconsistent extension normalization -> dangerous-type allow decision**. Do not publish web shells or attempt production execution; the evidence is the stored inert marker and decision table.

## Operator checklist

- [ ] Did the proof use only disposable prompt bundles, fake memory files, and temp upload roots?
- [ ] Were prompt loaders tested before any model/tool execution so parser-side impact is clear?
- [ ] Did file-read proofs use synthetic canaries instead of real secrets or system files?
- [ ] Did MCP evidence show both caller argument flow and retrieval/error-leak behavior?
- [ ] Did upload evidence compare validator input, storage name, final extension, and fixed behavior?
