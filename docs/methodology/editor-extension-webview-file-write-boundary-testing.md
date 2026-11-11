---
title: Code-editor extension webview and file-write boundary testing
---

# Code-editor extension webview and file-write boundary testing

Use this workflow during authorized assessment of VS Code (and compatible) editor extensions that render workspace or user content inside webviews. The ProjectDiscovery August 2026 audit of **Markdown Preview Enhanced** (~9.5M installs) produced a complete, replayable chain from "open a crafted README" to arbitrary local file write, plus a workspace-config-file sandbox escape to OS command execution. The durable pattern: a developer tool that auto-updates and runs with the user's privileges is an untracked supply-chain surface, and its webview-to-host message bridge is only safe if the host treats inbound messages as untrusted.

Primary records:

- WaveDrom diagram block evaluated as JavaScript in the preview, then to arbitrary file write: [CVE-2026-50733](https://nvd.nist.gov/vuln/detail/CVE-2026-50733), fixed in v0.8.28;
- Workspace config file (`.crossnote/config.js` / `parser.js`) evaluated with `vm.runInNewContext`, a non-security realm, yielding OS command execution: [CVE-2026-54566](https://nvd.nist.gov/vuln/detail/CVE-2026-54566), fixed in v0.8.29 (QuickJS-in-WASM), advisory [GHSA-427h-jhpr-8jch](https://github.com/advisories/GHSA-427h-jhpr-8jch);
- `.crossnote/head.html` raw-injected into the webview `<head>`, executing before the sanitizer initializes, providing a second webview XSS entry point: [CVE-2026-54701](https://nvd.nist.gov/vuln/detail/CVE-2026-54701), fixed in v0.8.30, advisory [GHSA-mcwg-4j78-qwv3](https://github.com/advisories/GHSA-mcwg-4j78-qwv3);
- Unrestricted webview-message-to-`vscode.commands.executeCommand` dispatch (30+ registered commands reachable): [CVE-2026-54702](https://nvd.nist.gov/vuln/detail/CVE-2026-54702), fixed in v0.8.30; and
- `updateMarkdown` writes any content to any `file://` URI with no containment: [CVE-2026-54703](https://nvd.nist.gov/vuln/detail/CVE-2026-54703), fixed in v0.8.30.

Source: [ProjectDiscovery, "Supply Chain Security Analysis of a 9.5M-Install VS Code Extension"](https://projectdiscovery.io/blog/a-9-5m-install-vs-code-extension-one-markdown-file-and-a-supply-chain-foothold).

!!! warning "Inert canaries and owned dev machines only"
    All proof below uses a disposable dev workspace, marker files, and denied process/file sinks. Do not write real shell startup files, SSH keys, or Git hooks, do not execute OS commands on a shared or production machine, and do not exfiltrate developer credentials.

## Why this is an offensive surface

Editor extensions auto-update and run with the user's privileges on the machine that holds source code, SSH keys, and publishing credentials, yet they rarely appear in a software bill of materials. Two trust boundaries matter:

1. **Content -> webview code.** Anything that renders workspace/user content (Markdown, diagrams, HTML includes) into a webview can become code execution in that webview.
2. **Webview -> host bridge.** `postMessage` from the webview to the extension host is only safe if the host validates the message before dispatching it to commands or writing files.

"Write any file" in a developer context is a pivot to code execution once the write targets something the system later reads and trusts:

- Shell startup files (`~/.bashrc`, `~/.zshrc`): file-write-to-RCE on the next shell.
- Git hooks (`.git/hooks/pre-commit`, `post-checkout`): runs on the next ordinary Git operation.
- Build/tooling config (`.vscode/tasks.json`, lint/test configs, dependency manifests): runs on the next build or install.
- `~/.ssh/authorized_keys`: append a key (proof only, never actually done).

## Inputs

- Written authorization for extension/webview testing on an owned or customer-approved machine.
- The target extension name, version range, and its renderer features (diagram formats, code chunks, HTML includes, exports).
- A disposable dev workspace you fully control.
- The extension's registered command list (inspectable from the source or by enumerating `vscode.commands` in the webview).

## Test matrix

| Boundary | What to vary | Evidence to capture |
| --- | --- | --- |
| Content-to-code | Diagram block languages allowed through the sanitizer (e.g., `wavedrom`, `text/tikz`), code chunks, HTML `head.html` includes | Whether renderer data reaches an `eval`/`Function`/`vm.runInNewContext`/in-JS interpreter |
| Sanitizer coverage | Server-side (Cheerio) vs client-side (DOMPurify) layers; parse-time vs post-hydration timing | Which layer sees which content and when the sanitizer initializes |
| Webview->host dispatch | Message `command` field values against the extension's registered commands | Whether unknown/extra commands reach `executeCommand` (allowlist or not) |
| File-write containment | `updateMarkdown`-style URI argument: in-workspace vs sibling vs absolute vs dot-dot | Canonical destination before the write; denied writer |
| Workspace config eval | `.crossnote/config.js` / `parser.js` / other config files loaded at init | Whether config is `eval`'d, `vm`'d, or run in an isolated engine (QuickJS/WASM) |
| Realm isolation | `this.constructor.constructor` / `getBuiltinModule` from the config-eval context | Host `process`/`Function`/`Object` reachable from the guest realm |

## 1. Find the content-to-code edge in the renderer

Open a benign control Markdown file and confirm the preview renders. Then, in an owned workspace, place inert markers in each diagram/format the extension supports and inspect the renderer source (or a breakpoint) for where diagram text is evaluated:

```text
const content = window.eval(`(${text})`);   // text from the Markdown file
```

Confirm which diagram types survive the sanitizer allowlist. The key distinction: the sanitizer preserved script-like diagram types so diagram data would survive rendering, but a later feature treated that preserved content as code. Record the exact renderer function, the allowed type set, and the evaluation call. A bounded positive is **crafted diagram content -> renderer eval -> inert canary string observed executing in the webview console**, not real payload execution.

## 2. Separate sanitizer layers by timing

Many editor extensions run two sanitizers: a server-side HTML pass (Cheerio) and a client-side pass (DOMPurify). Content injected into `<head>` (for example via a `head.html` include) can execute at parse time, before the React app and before DOMPurify have initialized. Verify:

- Which layer processes which content region (body vs head vs template).
- The initialization order relative to the injected content.
- Whether a `head.html`/include path bypasses both passes.

A bounded positive is **inert marker script in the include path -> executed before sanitizer init -> canary captured in the webview**, with no sanitizer pass touching that region.

## 3. Trace webview messages to command dispatch

From the webview, the extension typically exposes `acquireVsCodeApi()` and routes messages to a dispatcher. Inspect the dispatcher for allowlists:

```text
webview.onDidReceiveMessage((message) => {
  vscode.commands.executeCommand(`_prefix.${message.command}`, ...message.args);
});
```

If `message.command` is concatenated into a command name with no allowlist, enumerate the extension's registered commands and record which are reachable from the webview (e.g., `runCodeChunk`, `export` commands, `openInBrowser`). A bounded positive is **webview message with an attacker-chosen command name -> dispatch recorder**, showing the set of host commands reachable. Do not invoke destructive host commands; use inert/observable ones or a patched `executeCommand` recorder.

## 4. Resolve file-write commands at the final filesystem operation

For commands that write (an `updateMarkdown(uri, content)`-style internal sync API), test the containment:

- in-workspace path (control);
- sibling directory path;
- absolute path;
- `..` traversal;
- a path the extension did not open.

Patch `vscode.workspace.fs.writeFile` (or a downstream OS sink) with a recorder before sending the message. A bounded positive is **webview message -> `file://` URI outside the previewed file's boundary -> denied writer receives the canonical sibling/absolute path**. File-write reach is sufficient; do not actually overwrite a startup file, key, or hook.

## 5. Test workspace-config evaluation and realm isolation

Extensions that load `.crossnote/config.js` (or similar) at preview init may evaluate it with Node's `vm.runInNewContext`, which is explicitly **not** a security mechanism. From the guest context, `this.constructor.constructor` can yield the host `Function` constructor, and `process.getBuiltinModule('child_process')` (Node 22.3+) can reach the host runtime.

Verify the fixed posture: config evaluated inside QuickJS compiled to WebAssembly (guest intrinsics and heap, only explicitly marshaled values cross), with security-sensitive keys (`enableScriptExecution`, `chromePath`, `pandocPath`) stripped from untrusted config output.

A bounded positive on an unfixed build is **inert marker in config.js -> host `process`/`Function` reachable -> denied `child_process`/shell recorder**, without executing a command. On a fixed build, confirm the guest realm cannot reach host constructors.

## 6. Prove the persistence pivot without executing it

To demonstrate the file-write-to-code-execution pivot without executing anything, target a benign marker location and confirm the write lands:

- A marker file in the workspace `.git/hooks/` directory (denied, or a synthetic hook that only prints a canary to a log).
- A marker in a throwaway `~/.config/testtool/rc` you created for the test.

Record the canonical path and the denied/recorded write. The report states the pivot target class (shell rc, Git hook, build config) and the demonstrated write primitive; it does not need to execute the persisted code.

## Reporting heuristics

- Lead with the trust boundary that failed:
  - content-to-code: a diagram/include rendered into a webview reaches an evaluator.
  - bridge: a webview message reaches host command dispatch or a file writer without validation.
  - realm: a workspace config file is evaluated in a realm that shares host constructors.
- Include preconditions: extension version, which renderer features are enabled, whether the file was opened in an owned workspace, and the Node/VS Code host version.
- Avoid overclaiming. Webview XSS alone without a host-bridge or file-write primitive is a weaker finding; pair it with the dispatch or write proof.
- Treat the extension as a supply-chain artifact: note its install count, auto-update behavior, and that it is absent from typical SBOMs.
- Keep every payload inert: canary strings, marker files, denied process/file sinks. No credential capture, no real persistence, no shared-machine execution.
