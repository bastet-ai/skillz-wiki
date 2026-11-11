---
title: Downloader artifacts, remote-file synchronization, and MCP URI boundaries from July 24 GHSA updates
---

# Downloader artifacts, remote-file synchronization, and MCP URI boundaries from July 24 GHSA updates

Three July 24 updates yield durable checks for data that crosses more than one parser or trust layer: media metadata becoming an executable desktop shortcut, a remote file server choosing client filesystem destinations, and an MCP resource URI becoming SQL syntax.

Sources:

- [GHSA-6v4j-43gg-vj32: yt-dlp shortcut output injection](https://github.com/advisories/GHSA-6v4j-43gg-vj32) / CVE-2026-55404
- [GHSA-792x-6vq6-j8r9: Spring Integration remote-server path write](https://github.com/advisories/GHSA-792x-6vq6-j8r9) / CVE-2026-40987
- [GHSA-mvq4-39wx-6h5g: mysql-mcp-server URI SQL injection](https://github.com/advisories/GHSA-mvq4-39wx-6h5g) / CVE-2026-11529

!!! warning "Authorized validation only"
    Use an owned media page, disposable download directory, mock FTP/SFTP/SMB server, scratch database, and inert marker files/rows. Do not generate shortcuts that launch real commands, overwrite startup/configuration files, connect to third-party file servers, or query production databases.

## yt-dlp: metadata to trusted shortcut file

Before yt-dlp 2026.7.4, `--write-link` output could carry attacker-controlled metadata into operating-system shortcut semantics:

- Windows `.url` output could retain an untrusted `file://` `webpage_url`, turning a generated link into a remote-file launch decision when opened.
- Linux `.desktop` output combined with `--no-windows-filenames` could retain newlines in the generated filename, introducing new desktop-entry keys and changing `Type=Link` semantics.

### Parse-only artifact proof

1. Host an owned page whose video metadata includes unique harmless URL, title, and newline canaries. The media itself should be a tiny inert fixture.
2. Run the exact application wrapper with and without `--write-link`, platform-specific link selection, and `--no-windows-filenames`. Keep the test VM offline except for the owned fixture.
3. Do **not** open the generated shortcut. Parse it as text and record duplicate groups/keys, final `Type`, `URL` scheme/authority, and whether metadata created a new field.
4. Compare default sanitization, a normal title/URL, `--load-info-json` if the application uses it, and yt-dlp 2026.7.4.

Report **untrusted extractor metadata -> generated shortcut grammar -> changed launch target/type**. A generated media filename alone is not code execution, and user or automation execution of the shortcut remains a separate precondition.

## Spring Integration: remote names to local filesystem destinations

Affected `spring-integration-file` versions include 7.0.0-7.0.4, 6.5.0-6.5.8, 6.4.0-6.4.11, 6.3.0-6.3.14, and 5.5.0-5.5.20. A malicious or compromised FTP, SFTP, or SMB server can return names that make the client write controlled content outside its configured local directory. Version 7.0.5 is a fixed control for the 7.x line; verify the maintained fixed release for older branches from the advisory before testing.

1. Run the application client in a disposable container or VM with a configured local root and one synthetic sibling directory.
2. Serve ordinary, nested, absolute-looking, traversal-shaped, mixed-separator, and symlink-adjacent names from an owned mock server. Every body should contain only its filename-derived marker.
3. Capture the remote entry name, normalized relative name, resolved destination, open/write flags, and resulting tree. Stop at the first marker outside the local root.
4. Repeat across each protocol actually enabled by the target and on the fixed branch. Do not assume FTP behavior proves SFTP/SMB reachability.

Report **remote directory entry -> client path resolution -> outside-local-root marker write**. The attacker must control or compromise the configured remote server or its returned listing; this is not an unauthenticated inbound write to arbitrary Spring applications.

## mysql-mcp-server: URI fields to SQL grammar

`mysql-mcp-server` before 0.3.0 passes attacker-influenced `mysql://` resource URI material from `read_resource` into SQL construction. The reusable review target is the URI-to-query adapter: MCP clients may treat a resource URI as an identifier even when a server later interprets path/query components as SQL grammar.

1. Use a scratch database with two tables and one canary row each. Grant the MCP database user read-only access to this schema.
2. Invoke `read_resource` through the real MCP transport using a canonical resource URI, delimiter/quote canaries, encoded separators, and a boolean condition that changes only canary row count.
3. Log the parsed URI fields, parameterized query/argument array, database statement digest, and returned row IDs. Do not use stacked statements, time delays, file functions, metadata schemas, or credential tables.
4. Repeat on 0.3.0. The same URI components must remain bound values rather than changing SQL structure.

Report **MCP resource URI -> URI parser fields -> SQL grammar change -> synthetic result differential**. Do not infer broad agent compromise: document which principal can supply the URI, which MCP tool/resource is reachable, and the database privileges actually available.

## Evidence checklist

- exact package version and application feature/call-path reachability;
- raw metadata, remote name, or URI plus every normalized representation;
- generated artifact parse, resolved client path, or parameterized statement structure;
- marker-only effect and patched negative control;
- explicit downstream preconditions such as shortcut execution, remote-server control, MCP caller authority, and database grants.