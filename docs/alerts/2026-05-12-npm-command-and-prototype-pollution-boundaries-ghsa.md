# npm command and prototype-pollution boundary batch

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because small utility packages again crossed untrusted strings into shell commands, OCR helpers, object prototypes, or regular-expression engines.

## Advisories covered

- **`@jswork/next-npm-version` command injection** — [GHSA-2xx6-qf7x-grqh](https://github.com/advisories/GHSA-2xx6-qf7x-grqh): package/version helper input can become shell syntax when release automation shells out instead of using argv arrays and strict package-name validation.
- **`node-ts-ocr` command injection through `invokeImageOcr`** — [GHSA-8jh2-3mw6-6pfm](https://github.com/advisories/GHSA-8jh2-3mw6-6pfm): OCR wrappers are command-boundary code; image paths, language names, and engine options must not be concatenated into shell strings.
- **`query-string-parser` prototype pollution** — [GHSA-587p-w43q-4hjx](https://github.com/advisories/GHSA-587p-w43q-4hjx): query parsers must reject `__proto__`, `constructor`, and `prototype` keys before nested object materialization.
- **`parse-ini` prototype pollution** — [GHSA-x72j-hv9f-qqh4](https://github.com/advisories/GHSA-x72j-hv9f-qqh4): config parsers need null-prototype objects or denylisted magic keys so configuration files cannot mutate global object behavior.
- **`youtube-regex` ReDoS** — [GHSA-vpxx-h23g-gxh2](https://github.com/advisories/GHSA-vpxx-h23g-gxh2): URL recognizers should use bounded parsing and host/path checks instead of catastrophic regular expressions.

## Operator triage

1. Remove or patch affected packages; where no fixed version is listed, replace the package or isolate it behind strict input allowlists.
2. Search CI/release jobs and media/OCR pipelines for use of these packages with attacker-controlled package names, file paths, URLs, query strings, or INI/config data.
3. Hunt for unexpected child processes from Node services, especially OCR binaries or package-manager commands with arguments derived from requests or repository metadata.
4. For prototype-pollution exposure, test whether parsed query/config values can influence authorization flags, template locals, logging redaction, HTTP client options, or filesystem paths.

## Durable controls

- Use `spawn`/`execFile` with explicit argv arrays; never build shell command strings from request, package, file, or model-controlled data.
- Validate package names, versions, image paths, language identifiers, and URL hosts with narrow allowlists before passing them to tools.
- Parse nested objects into null-prototype containers and reject magic prototype keys at every nesting level.
- Prefer URL parsers and bounded string checks over broad regexes for URL classification.
- Treat utility packages in CI, release, and media-processing paths as privileged code because compromise or parser bugs often expose credentials and build hosts.
