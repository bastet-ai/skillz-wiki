---
title: Library URL, tenant authority, commerce binding, and file-boundary checks
---

# Library URL, tenant authority, commerce binding, and file-boundary checks

A July 31 advisory wave exposes reusable operator boundaries across SDK URL construction, SSRF validation, Kubernetes tenant controllers, payment callbacks, corpus readers, local developer servers, file-sharing tools, workflow imports, and server templates.

Sources:

- [GHSA-g956-2f74-rmv7](https://github.com/advisories/GHSA-g956-2f74-rmv7) covers unencoded path and query values in `hashi-vault-js` through 0.5.1;
- [GHSA-5846-7qm3-r52j](https://github.com/advisories/GHSA-5846-7qm3-r52j) covers `dssrf` accepting a loopback name after an empty DNS result through 1.0.4;
- [GHSA-qvv7-cg9c-w4x3](https://github.com/advisories/GHSA-qvv7-cg9c-w4x3) covers DNS rebinding between NLTK URL validation and connection through 3.9.4;
- [GHSA-jr6p-8pjj-mfx6](https://github.com/advisories/GHSA-jr6p-8pjj-mfx6) covers Capsule `TenantResource` raw-item and generator paths retaining cluster-scoped controller authority in 0.13.0 through 0.13.7;
- [GHSA-x83g-979r-f5fh](https://github.com/advisories/GHSA-x83g-979r-f5fh) and [GHSA-rc52-c4hv-w89p](https://github.com/advisories/GHSA-rc52-c4hv-w89p) cover Sylius Mollie Plugin order-token disclosure and payment-to-order misbinding;
- [GHSA-6hm5-jgcp-p838](https://github.com/advisories/GHSA-6hm5-jgcp-p838) and [GHSA-xh95-f55m-82fw](https://github.com/advisories/GHSA-xh95-f55m-82fw) cover NLTK corpus-reader paths that bypass `nltk.pathsec` through 3.9.4;
- [GHSA-g2r8-wvmj-jf5w](https://github.com/advisories/GHSA-g2r8-wvmj-jf5w) covers wildcard CORS on the `nx graph` local server;
- [GHSA-22p9-r2f5-22mf](https://github.com/advisories/GHSA-22p9-r2f5-22mf) and [GHSA-v833-3823-cmhp](https://github.com/advisories/GHSA-v833-3823-cmhp) cover OnionShare symlink following and disabled-upload sink enforcement before 2.6.4;
- [GHSA-g29c-rgq6-gxgj](https://github.com/advisories/GHSA-g29c-rgq6-gxgj) covers `awxkit` YAML `!include` traversal;
- [GHSA-f6vj-48fm-hmvx](https://github.com/advisories/GHSA-f6vj-48fm-hmvx) covers GCS object names escaping an Airflow Samba destination before provider 4.12.6; and
- [GHSA-pfvc-3p5h-x7h6](https://github.com/advisories/GHSA-pfvc-3p5h-x7h6) covers user-editable Pterodactyl egg values reaching Wings daemon configuration templates before 1.12.3.
- [GHSA-2jhm-w3mp-jcwr / CVE-2026-12372](https://github.com/advisories/GHSA-2jhm-w3mp-jcwr) covers NLTK strict network validation omitting RFC 6598 shared-address-space destinations in 3.9.4 and the then-current development branch.

!!! warning "Canaries only"
    Run these checks in disposable applications, clusters, stores, corpora, shares, repositories, and game-server nodes. Use fake Vault tokens, owned DNS/listener pairs, inert Kubernetes objects, synthetic orders and payments, marker-only files, no-op help commands, and fake template values. Never call a live Vault administrative endpoint, alter a real order, read customer data, access real local files, or retrieve node tokens and registry credentials.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| Vault SDK | path segment or query value | application token sends a different Vault request | mocked transport records changed path or parameters |
| SSRF helper | hostname and DNS outcome | validation result authorizes a later socket | owned listener B receives after listener A was approved |
| Capsule controller | raw item or generated kind | tenant object is applied with controller authority | admission recorder sees an inert cluster-scoped canary |
| Payment integration | order ID and provider payment ID | public route returns an order capability or mutates another order | synthetic two-order decision table differs by foreign ID |
| Corpus reader | file ID, frame name, or corpus index value | helper bypasses the documented path gate | parser returns an outside-root marker file |
| Local dev server | browser origin | arbitrary website reads loopback project responses | owned foreign origin reads a synthetic graph marker |
| Share/import/workflow tool | symlink, upload part, include, or object name | local process reads or writes beyond its stated boundary | disposable marker is read or written, with no sensitive target |
| Wings template | editable egg value | tenant input resolves against node configuration | fake non-secret config marker appears in a server file |

Prove authority, selection, and final sink separately. A malformed value accepted by a parser is not enough; preserve the final URL, Kubernetes object, selected order, opened path, written path, browser-readable response, or rendered marker.

## SDK URL-construction differential

Use a mocked HTTP adapter that cannot reach Vault. Configure a fake base such as `https://vault.invalid/v1/skillz/` and a token with no real authority.

1. Call each SDK method with an ordinary identifier and record the method, raw URL, normalized path, query multimap, headers, and body.
2. Repeat with one path-separator marker, one dot-segment marker, one percent-encoded marker, and one query-delimiter marker.
3. Parse the final URL with the same HTTP stack the application uses.
4. Compare vulnerable and fixed releases.

| Input class | Expected secure result |
| --- | --- |
| path identifier | remains exactly one encoded path segment |
| query scalar | remains exactly one value under the documented key |
| delimiter or dot-segment canary | rejected or encoded before transport dispatch |

A report should identify the application-controlled SDK method and the authority of its Vault token. Do not equate a path-normalization difference with access to an administrative endpoint unless an isolated fake Vault and a deliberately restricted token prove that separate authorization edge.

## SSRF validation-to-connection drift

Test both the empty-resolution branch reported for `dssrf` and the validation/connect-time rebinding reported for NLTK with owned infrastructure only.

### Empty-answer matrix

Stub the resolver so the same hostname produces each controlled outcome:

| Validation outcome | Address set | Secure policy |
| --- | --- | --- |
| public answer | owned public test address | allow only according to policy |
| loopback/private answer | synthetic blocked address | reject |
| empty/NXDOMAIN | no usable address | reject closed |
| resolver error | exception or timeout | reject closed |

The key assertion is that an empty answer must not turn a literal localhost or unresolved host into an allowed destination. Record the validator result and confirm that no socket was attempted.

### Rebinding harness

Use two owned listeners and deterministic resolver instrumentation:

```text
validation lookup -> owned listener A
connection lookup -> owned listener B
```

Listener B should return only `SKILLZ-FINAL-DESTINATION`. Capture lookup order, approved address set, connected peer, redirects, and response marker. A valid positive shows the validator approving A while the HTTP client independently resolves and connects to B. Do not use cloud metadata, loopback administration routes, or production private services.

### NLTK special-use destination matrix

The later NLTK record adds a classification gap independent of DNS rebinding: `validate_network_url()` reportedly rejects familiar private categories but can admit `100.64.0.0/10` because Python's `ipaddress` classification does not make that range either `is_private` or `is_global`. Test the validator and each reachable network-loading helper separately in a disposable namespace with no production routes.

Place an owned no-content listener on one lab-only RFC 6598 address. Compare a public test peer, loopback, RFC 1918, link-local, RFC 6598, IPv4-mapped forms, and an owned hostname resolving to each class. Record raw URL, parsed host, every DNS answer, `ipaddress` properties, validator verdict, final connected peer, and whether response bytes would be relayed. A bounded positive is **strict mode enabled -> RFC 6598 fixture passes validation -> the affected helper selects the owned listener**. A validator-only acceptance is a policy gap, not product-level SSRF, and must not be reported as network reachability without the connector trace. Never contact carrier infrastructure, VPN/shared services, metadata endpoints, or arbitrary hosts.

## Capsule alternate-path authority check

The reusable lesson is to test every representation accepted by a controller after a security fix, not only the route named by the guard.

### Preconditions

- disposable Kubernetes cluster and Capsule deployment;
- tenant owner with no direct cluster-scoped create permission;
- audit logging or a fake apply client;
- an inert custom resource or marker-only cluster-scoped fixture with no RBAC rules, webhook callbacks, or workload effects.

Build a matrix across `NamespacedItems`, `RawItems`, and `Generators`:

| Input path | Namespaced canary | Cluster-scoped inert canary | Expected secure result |
| --- | --- | --- | --- |
| selected item | allowed in tenant namespace | rejected before apply | scope guard covers selection |
| raw item | allowed in tenant namespace | rejected before apply | scope guard covers decode/render path |
| generator | allowed in tenant namespace | rejected before apply | scope guard covers generated objects |

Record the tenant principal, selected controller client, object GVK, namespace before and after rendering, discovery result for resource scope, and whether the apply sink was reached. Setting `metadata.namespace` is not confinement for a cluster-scoped kind. Stop at an inert marker and never create a `ClusterRole`, webhook configuration, CRD, namespace, or other operational cluster object.

## Payment and order object-binding workflow

Use a local Sylius store, a mocked Mollie adapter, and two disposable orders:

```text
Order A -> provider payment PA -> owner session A
Order B -> provider payment PB -> owner session B
```

No real payment is needed. Seed provider responses so both fake IDs have explicit synthetic status.

### Capability-disclosure edge

Request the QR and thank-you route families as anonymous, owner A, and owner B while substituting A, B, absent, and malformed order IDs. Capture status, redirect target shape, response schema, session changes, and whether any order capability appears. Redact the capability itself.

A positive requires a foreign or anonymous request to obtain a capability associated with the synthetic order. Do not follow it into customer pages or collect names, email addresses, addresses, or order lines.

### Payment-to-order binding edge

Replay the webhook handler through a local request recorder:

| Provider ID | Order ID | Expected secure result |
| --- | --- | --- |
| `PA` | A | process A according to mocked provider status |
| `PB` | B | process B according to mocked provider status |
| `PA` | B | acknowledge safely, no mutation |
| unknown | A | no mutation |

Preserve the incoming pair, server-side payment ID stored on the order, mocked provider result, transition decision, and before/after synthetic state. The finding is an object-binding failure, not a payment-provider verification bypass: one identifier may be valid while belonging to a different object.

## NLTK corpus sandbox coverage

Create this disposable layout:

```text
/tmp/skillz-nltk/
  corpus/                 # configured root
  sibling/
    marker.xml            # synthetic parser-valid canary
```

Enable `nltk.pathsec.ENFORCE = True`, instrument both `CorpusReader.open()` and the builtin file-open sink, and exercise:

- `NKJPCorpusReader` public methods with ordinary and traversal-shaped `fileids`;
- `FramenetCorpusReader.frame()` with an ordinary name and a sibling-marker name;
- FrameNet document and lexical-unit filenames sourced from a synthetic corpus index; and
- fixed-version controls using the identical fixture.

Capture requested logical name, normalized absolute path, required root, which open helper was called, and returned marker. The strongest evidence shows that the documented secure mode is active but a specialized reader reaches builtin `open()` without invoking the central validator. Never target `/etc`, home directories, credentials, notebooks, datasets, or model artifacts.

## Loopback developer-server browser boundary

Start `nx graph` against a repository containing only synthetic project names and a help command that prints `SKILLZ-NX-HELP`. Keep it bound to loopback. From an owned foreign-origin page, issue browser `fetch()` requests to the graph and help routes.

Record:

- bind address and port;
- browser page origin;
- request method and preflight behavior;
- response CORS headers;
- whether JavaScript can read the synthetic graph/help marker; and
- vulnerable/fixed release results.

The valid finding is cross-origin readability of loopback responses. The advisory notes that the help command comes from existing workspace configuration rather than the browser request. Do not claim browser-supplied command execution, and do not place a malicious command in a real repository merely to amplify the result.

## Share, import, and workflow filesystem checks

### OnionShare symlink read

Create a share directory and a sibling marker, then place a symlink inside the share pointing only to that marker. Test Website mode, individual Share download, and generated archive paths separately. Capture index mapping, dereferenced path, archive listing, and returned marker. Raw URL traversal is a different hypothesis and should not be claimed from a symlink result.

### OnionShare disabled-upload sink

Start Receive mode with file uploads disabled and submit a small multipart canary named `skillz-marker.txt`. Instrument the stream factory and receive directory. A positive requires file creation or a write event despite the disabled setting; hiding the browser input or omitting the file from later accounting is not sink enforcement. Delete the fixture immediately.

### `awxkit` include boundary

Use a disposable import directory and a sibling YAML marker containing only `skillz: include-canary`. Import a synthetic document whose `!include` value selects that sibling. Record the importer's normalized path and parsed marker. Do not point the include at credentials, AWX configuration, SSH material, or shell files.

### Airflow GCS-to-Samba write boundary

Use fake GCS and SMB adapters backed by temporary directories. Seed one normal object name and one object name that would normalize to a sibling marker path. Record source object name, configured destination root, normalized destination, containment decision, and write-recorder event. The positive is an outside-root marker write caused by object metadata; do not connect to a real bucket or Samba share.

## Wings egg-to-node template boundary

Run Panel and Wings in an isolated node whose configuration contains only a fake field such as:

```yaml
skillz_canary: NODE-CONFIG-MARKER
```

Use a stock-like egg fixture where an editable environment variable is rendered into a server-owned configuration file. Submit a harmless template-shaped value that references only `skillz_canary`, then record:

1. the user-editable value accepted by Panel;
2. the replacement definition sent to Wings;
3. the template context keys exposed by Wings; and
4. whether the server file contains the literal placeholder or `NODE-CONFIG-MARKER`.

Do not request `token`, `token_id`, registry credentials, environment variables, or any real daemon field. A report should distinguish editable-variable permission, Panel substitution, Wings template evaluation, and server-file readability. The canary proves the authority transition without obtaining reusable credentials.

## August 7 follow-up: test NLTK package identity at the final extracted resource

[GHSA-ffj6-66c4-86gw / CVE-2026-12261](https://github.com/advisories/GHSA-ffj6-66c4-86gw) reports a different NLTK boundary through 3.9.4: `nltk.downloader` extracts archives into shared namespaces such as `corpora/` and `taggers/`, then performs integrity validation after write and extraction. A package can therefore place a member at another package's ordinary lookup path, and the poisoned resource remains active across interpreter restarts. The record was unreviewed at scan time; confirm the exact downloader build, index metadata, archive layout, and corrected behavior before reporting.

Treat this as **package identity to resource identity drift**, not ordinary archive traversal. A destination can remain inside the configured NLTK data root while still overwriting a resource owned by a different package.

### Disposable two-package harness

1. Set `NLTK_DATA` to a new temporary directory containing no real corpora, models, credentials, or shared cache. Block outbound networking and serve package metadata plus archives from an owned local fixture.
2. Define package A with one synthetic resource, for example `corpora/skillz_a/marker.txt`. Define package B whose declared identity is different but whose archive also contains that exact member path with a distinct inert marker.
3. Instrument archive-member resolution, file open/write/replace operations, integrity-check timing, package-status bookkeeping, and the ordinary NLTK resource lookup. Deny writes outside the temporary root even though this hypothesis does not require root escape.
4. Install A, hash its marker, then install B. Preserve B's declared package ID, archive member name, canonical destination, A's before/after hash, and whether any validation failure occurs before or after the write.
5. Start a fresh interpreter and load A's resource through the normal API. A positive requires B's marker to be selected under A's canonical resource name after restart; archive acceptance or an observed path collision alone is insufficient.
6. Add controls for disjoint package paths, duplicate members inside one archive, failed archive integrity, interrupted extraction, package removal/reinstall order, read-only existing resources, and the corrected build.
7. Repeat with one synthetic path in each shared namespace the application actually uses. Do not substitute real `punkt`, tokenizer, tagger, corpus, or model files and do not run a model trained or configured by the fixture.

The bounded result is **package B selected for installation -> B member resolves to package A's existing canonical resource -> write/replace recorder accepts the collision -> fresh interpreter loads B's inert marker through A's normal resource lookup**. Report shared-namespace overwrite and persistent resource selection; do not infer code execution, model compromise, or downstream data poisoning unless a separate authorized inert sink proves that edge.

Record package identity and archive identity independently. A secure control should reject cross-package ownership collisions before extraction becomes visible, stage writes outside the active namespace, validate the complete package, and publish the package atomically without replacing another package's owned paths.

## August 25 NLTK follow-up: proxy drift, dot search-path, XXE, and pickle

Four later NLTK records (all through `3.10.3`, the pickle one through `3.9.4`) extend the same library-surface theme. Confirm the exact build and corrected behavior before reporting; all were unreviewed at scan time.

### Proxy validation-to-connection drift ([GHSA-crp9-r7rq-c8cg](https://github.com/advisories/GHSA-crp9-r7rq-c8cg))

`nltk.pathsec.urlopen` validates the requested hostname locally, but when an HTTP proxy is configured the proxy-handler inheritance disables the safe HTTP/HTTPS handlers, so the actual fetch goes to the proxy against a destination that is never re-validated. This is the same **validation-to-connect drift** as the DNS-rebinding and RFC 6598 items above, with the drift now at the proxy hop.

Use an owned no-content proxy and two owned peers:

```text
validate lookup  -> owned public peer A
delivery fetch   -> owned loopback/private peer B (via proxy)
```

Supply a validated public URL and have the proxy forward to B. Record the validator verdict, the proxy target, and the final connected peer. A bounded positive is **strict mode enabled -> public URL passes local validation -> proxy forwards to the owned private peer**. Never reach cloud metadata, loopback admin routes, or production private services. A proxy-only acceptance without the connect trace is a policy gap, not product-level SSRF.

### Graphviz `dot` search-path resolution ([GHSA-54xp-3ww7-6wjg](https://github.com/advisories/GHSA-54xp-3ww7-6wjg))

`dependencygraph.dot2img` and `AlignedSent._repr_svg_` invoke the `dot` binary by bare name instead of a validated absolute path. Place an inert `dot` canary on the current working directory (Windows) or a relative `PATH` entry (Unix) and record which binary the resolver selects. A positive is the library selecting the CWD/`PATH` canary over the legitimate tool. Prove binary-resolution drift only; do not execute a real payload.

### `ElementTree` entity-expansion DoS ([GHSA-jx89-3qg8-p2mr](https://github.com/advisories/GHSA-jx89-3qg8-p2mr))

Multiple modules parse XML with `xml.etree.ElementTree`, which honors DTD entity declarations. Craft a document whose nested entities expand from bytes to megabytes and record the parse-time memory growth. Treat this as a bounded DoS/XXE-surface note: prove the expansion differential against a fixed build; do not claim arbitrary file read or OOB write without a separate authorized sink.

### `TransitionParser.parse` unrestricted pickle ([GHSA-gx65-c5hj-vpv5](https://github.com/advisories/GHSA-gx65-c5hj-vpv5))

`TransitionParser.parse()` calls `pickle_load()` with the default `restricted=False`, routing through `WarningUnpickler`, which does not override `find_class()` and so permits arbitrary class resolution. When an application loads an attacker-crafted model file, embedded pickle gadgets execute as the application user. `RestrictedUnpickler` exists but is not used on this production path.

Prove the class-resolution gap with a synthetic pickle that references an inert canary class and a denied `__reduce__` sink; confirm `find_class` resolves the canary without executing it. Do not ship a real RCE gadget or run it on a shared host. Report the deserializer-selection flaw with the exact `pickle_load` call site and the `restricted` default.

## September 4 NLTK follow-up: pathsec default-off and DNS-resolution SSRF fail-open

Two later NLTK records (both through the current `3.x` line) extend the same library-surface theme. Confirm the exact build and corrected behavior before reporting.

### `pathsec` default `ENFORCE=False` disables all controls ([GHSA-p3m8-78j2-g5p3](https://github.com/advisories/GHSA-p3m8-78j2-g5p3) / CVE-2026-62388)

`nltk.pathsec` ships with `ENFORCE=False` as the default, which disables *all* of its path-security controls — the URL validation, the file-open sandbox, and the downloader namespace confinement described throughout this page are inert unless an application explicitly opts in. The durable operator check: in any target that uses NLTK network/corpus loading, confirm whether `pathsec.ENFORCE` is actually set in the running configuration (code audit, env/config, or a behavior probe) rather than assuming the library self-protects. A library that is safe by default only in review and unsafe by default in the wild is a **configuration-trust boundary**, not a code boundary: the report is which deployment paths leave `ENFORCE` at its default.

### `validate_network_url()` SSRF fail-open via DNS resolution ([GHSA-3gqm-fcw5-w839](https://github.com/advisories/GHSA-3gqm-fcw5-w839) / CVE-2026-63311)

`validate_network_url()` can fail open through DNS resolution: when the resolver returns an answer the validator does not classify into a blocked category (or the lookup path errors in a way the validator treats as "not blocked"), the URL passes validation even though it resolves to a private/loopback/metadata destination. This is the same **validation-to-connect drift** as the DNS-rebinding, RFC 6598, and proxy-hop items above, with the drift now in the resolver-answer classification step.

Use two owned peers in a disposable namespace with no production routes:

```text
validate   -> owned name that resolves to a blocked-lookalike / unclassified answer
connect    -> owned private/loopback peer B that the resolver actually returns
```

Record the validator verdict, the resolver answer (family, address, classification), and the final connected peer. A bounded positive is **validation passes -> resolver returns a destination the validator did not classify as blocked -> fetch reaches the owned private peer**. Never reach cloud metadata, loopback admin routes, or production private services.

## September 8 NLTK follow-up: four file-boundary bypass paths past `pathsec` and the downloader gate (4 GHSAs)

Four reviewed NLTK records (patched in `3.9.3`/`3.10.0`) add concrete bypass paths to the same `pathsec`/corpus-escape theme documented above. The durable operator lesson is sharper than any single one: **a lexical sandbox guard that compares a path to itself, opens via `builtins.open`, resolves symlinks only lexically, or downloads before verifying is a file-boundary that fails at a different step every time.** In any target that loads NLTK data or corpora, inventory which of the four failure classes the running build exhibits — not just whether `ENFORCE` is on.

### 1. `StreamBackedCorpusView._open()` bypasses `pathsec` even with `ENFORCE=True` ([GHSA-x5ph-mj9p-rfr8](https://github.com/advisories/GHSA-x5ph-mj9p-rfr8))

`nltk.pathsec.open` is the documented enforcement point: it calls `validate_path(file)` before `builtins.open`. `StreamBackedCorpusView._open()` in `nltk/corpus/reader/util.py` does **not** route through it — for string `fileid` values it calls `builtins.open()` directly on the raw string. The effect: with `pathsec.ENFORCE = True` (the setting the earlier `ENFORCE=False` default-off item says you must confirm is set), any corpus view that reaches `StreamBackedCorpusView` — including `XMLCorpusView` and any subclass that passes a raw string `fileid` — still reads arbitrary local files.

Reproducible check in a disposable install: set `ENFORCE=True`, point a `StreamBackedCorpusView`/`XMLCorpusView` at a root, and pass a `fileid` that is an absolute path to an **inert canary file** outside the data directories. A positive is the canary content returned while `pathsec.validate_path` would have raised for the same path via `pathsec.open`. The report is the bypass call site (`_open` → `builtins.open`), not "file read". Never use the bypass to read credentials, keys, or other tenants' data in an authorized target; prove the gap against your own canary only.

### 2. `FileSystemPathPointer.open()` sandbox guard is dead code — `normpath` compared to itself ([GHSA-72r2-7mfr-5xr9](https://github.com/advisories/GHSA-72r2-7mfr-5xr9))

`nltk/data.py` carries a "SECURITY PATCH ENFORCING SANDBOX" comment in `FileSystemPathPointer.open()`, but the guard condition is `os.path.isabs(path) and path != os.path.normpath(self._path)` where `path` was *just assigned* `os.path.normpath(self._path)` — the comparison is always `False`, so the branch can never fire. The result: **any file the process can read is reachable by passing a `file://` URL to `nltk.data.load()`**, because the "direct absolute access" check does not execute at all.

Reproducible check: in a disposable install, `nltk.data.load("file:///absolute/path/to/canary.txt")` where the canary sits outside the NLTK data root. A positive is the canary bytes returned despite the guard's comment claiming it blocks raw absolute reads. The report is the tautological guard expression itself — a "security patch" that structurally cannot trigger — plus the call chain from `nltk.data.load` to `open()`.

### 3. `CorpusReader` symlink escape: lexical boundary check does not resolve symlinks ([GHSA-r6gq-whwq-mvg9](https://github.com/advisories/GHSA-r6gq-whwq-mvg9))

`CorpusReader.open()` blocks absolute paths and `..` traversal, then opens `self._root.join(file)`. The check is **lexical**: it never resolves the final path, so a symlink placed *inside* the corpus root points outside it and the reader follows it. Combined with items 1 and 2, this is the third distinct failure class for the same boundary: absolute path, `..`, and symlink resolution are three separate gates, and each of the four records in this section shows a different one being absent or inert.

Reproducible check: in a disposable corpus root (one you own and created), place a symlink whose target is an **inert canary file** just outside the root. Load it through `CorpusReader.open()`. A positive is the canary content read through the symlink. Never point symlinks at credentials, config, or other tenants' data; the proof is "symlink outside root was followed", recorded with the link path and target path only.

### 4. Downloader: no post-download integrity check before extraction ([GHSA-5wp5-5229-5g6q](https://github.com/advisories/GHSA-5wp5-5229-5g6q))

`nltk/downloader.py` downloads a package archive to a temp path over HTTP, moves it to the final location with `os.replace`, and then extracts it. The SHA-256 verification logic exists in `_pkg_status()` but is only used **before** download ("is this package already installed and up-to-date?") — it is never applied to the file that was actually received. The attack surface is classic supply-chain: MITM on an `http://` mirror, a compromised mirror, or a local race between the move and the extraction. This extends the archive-extraction theme already tracked in this taxonomy: the boundary is *where the integrity check sits relative to extraction*, and here it sits on the wrong side of it.

Reproducible check: stand up a disposable local mirror serving a **canary package archive** whose contents you control, point a patched-vs-unpatched NLTK build at it, and record (a) whether the unpatched build extracts without any post-download verification, and (b) that the patched `3.9.3`/`3.10.0` build verifies before extraction. Use inert files only; do not plant executable payloads in an extraction path that a real application would run, and do not test against a production mirror or a shared corpus cache.

**Cross-cutting lesson for NLTK targets.** For each of the four, the failing control is a *different* step in the same pipeline: enforcement routing (item 1), guard logic (item 2), path resolution (item 3), and check ordering (item 4). When auditing any corpus/data-loading library, test each step separately — a green "ENFORCE is on" does not cover any of them.

## Evidence and reporting

For every workflow, preserve:

- exact package, version, configuration, and reachable application feature;
- low-privilege or anonymous precondition;
- normal, malformed, foreign-object, and fixed-version controls;
- normalized URL, destination, object identity, or template context at the final sink;
- marker-only output and cleanup confirmation; and
- the narrow authority gained by the tested edge.

Prefer titles such as “Vault SDK path identifier changes the mocked downstream route,” “Capsule raw-item path reaches apply with a cluster-scoped canary,” “paid-provider ID is accepted for a different synthetic order,” or “Wings renders a user-editable value against node configuration.” Avoid generic Vault compromise, cluster-admin takeover, payment fraud, arbitrary file theft, or node compromise unless those stronger outcomes were independently authorized and safely proven.