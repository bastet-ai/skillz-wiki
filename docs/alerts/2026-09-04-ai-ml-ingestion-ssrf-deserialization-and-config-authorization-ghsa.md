# AI/ML ingestion boundaries: URL-partitioning SSRF, SSRF redirect bypass, checkpoint deserialization, and non-superuser LLM-config overwrite (GHSA)

Source: hourly offensive-security scan, 2026-09-03/04 GitHub advisory `updated` wave. Durable because these five records span the two most reusable AI/ML operator axes this wiki already carries — **ingest-then-fetch SSRF** and **trusted-artifact deserialization/RCE** — plus a new **AI-platform global-config authorization** axis (Cognee). Each is a distinct trust boundary, but the audit pattern is the same: untrusted material (a URL, a checkpoint file, a config write) crosses from "input" to "server-side authority" without the expected gate.

Primary entries:

| GHSA | Product | Boundary | Defect | Severity |
| --- | --- | --- | --- | --- |
| [GHSA-4MVJ-M6J5-PMF7](https://github.com/advisories/GHSA-4mvj-m6j5-pmf7) / CVE-2026-71428 | `unstructured` (pip `>= 0.4.7, < 0.24.0`) | URL-based partitioning SSRF | the partitioner fetches caller-supplied URLs server-side without an allow/deny network gate | critical 9.3 |
| [GHSA-MR4R-HCGX-8P4H](https://github.com/advisories/GHSA-mr4r-hcgx-8p4h) / CVE-2026-62240 | `crewai-tools` (pip `< 1.15.1`) | Tool fetch SSRF redirect bypass | an initial-URL SSRF check is applied but the redirect response follows to an internal/synthetic-denied host | high 7.4 |
| [GHSA-QQMF-GPG7-G8GW](https://github.com/advisories/GHSA-qqmf-gpg7-g8gw) / CVE-2026-58659 | `lightning` / PyTorch Lightning (pip `< 2022.6.15` line) | Checkpoint `_instantiator` hyperparameters | loading a checkpoint invokes user-supplied `_instantiator` callables → arbitrary code execution | high 7.8 |
| [GHSA-997V-R4V7-9F3G](https://github.com/advisories/GHSA-997v-r4v7-9f3g) / CVE-2026-15529 | `pyod` (pip `>= 3.5.0, < 3.6.2`) | `persistence.load` deserialization order | untrusted artifacts are deserialized *before* validation, so a malicious pickle payload executes on load | medium 6.3 |
| [GHSA-49F7-WHX5-4256](https://github.com/advisories/GHSA-49f7-whx5-4256) / CVE-2026-58473 | `cognee` (pip `< 1.5.0`) | Global LLM configuration authorization | a non-superuser can overwrite the platform-wide LLM configuration | critical 9.1 |

!!! warning "Authorized validation only"
    Keep proofs to disposable lab instances with synthetic checkpoints/URLs, owned no-content peers, and denied network/file/process sinks. Prove SSRF with an owned callback, not metadata or RFC1918 production hosts. Prove deserialization with an inert canary payload that writes one marker, not real data. Prove the Cognee config boundary with a synthetic non-superuser and a canary config value. Do not load untrusted model code on production workers, read real LLM keys, or mutate a live shared deployment.

## Boundary map

| Product | Input | Trust break | Reusable check |
| --- | --- | --- | --- |
| `unstructured` | URL passed to the partitioner | no server-side fetch gate | Partition a URL that points at an owned listener; record whether the server dialed it and whether a denied-destination URL is blocked. |
| `crewai-tools` | Tool-fetch URL + redirect | check applied to hop 0, not the post-redirect host | Have an owned redirector 301 to a second owned "denied" listener; record the decision vs the final dial. |
| `lightning` checkpoint | checkpoint file with `_instantiator` | checkpoint treated as trusted artifact | Load a synthetic checkpoint whose `_instantiator` is a marker callable; record whether it is invoked. |
| `pyod` artifact | serialized artifact to `persistence.load` | deserialize-before-validate order | Feed a marker pickle that writes one file on `__reduce__`; record whether it runs before the validator. |
| `cognee` | config-write request from non-superuser | role gate not applied to global LLM config | As a synthetic non-superuser, attempt one benign config change; record whether the global LLM config is written. |

## Replayable validation boundaries

### `unstructured` URL-partitioning SSRF

1. Stand up a disposable `unstructured` (vulnerable line `>= 0.4.7, < 0.24.0`) with network access limited to your owned listeners.
2. Run the URL-based partitioner against (a) an owned callback URL and (b) a synthetic denied destination (your "internal" listener). Record which are fetched and which are blocked.
3. A positive is the server dialing a caller-supplied URL with no allow/deny gate. Keep it to the callback nonce; do not fetch metadata, cloud endpoints, or internal services.

### `crewai-tools` SSRF redirect bypass

1. Use two owned listeners: A (initial, allowed-looking) and B (synthetic "denied"/internal target).
2. Configure A to 301-redirect to B. Drive the tool's fetch at A.
3. A positive is the SSRF gate evaluating the initial URL but the request ultimately reaching B. Record the validated host, the redirect hop, and the final dialed host. Do not use uncontrolled public redirects or cloud metadata.

### PyTorch Lightning checkpoint `_instantiator` RCE

1. Build a minimal synthetic Lightning checkpoint whose hyperparameters contain an `_instantiator` field naming a marker callable (a function whose only effect is to append a fixed line to a disposable log).
2. In a disposable training/inference process, load that checkpoint. Record whether the marker callable is invoked.
3. Negative control: a checkpoint with no `_instantiator`, and the patched build. Do not point `_instantiator` at real credentials, model weights, or cloud config; the proof is "callable invoked on load," not data access.

### `pyod` `persistence.load` deserialization-before-validation

1. Create a marker artifact whose deserialization (`__reduce__` or equivalent) writes one inert file to a disposable path.
2. Call `persistence.load` on it in a disposable process. Record whether the marker write occurs, and *before* any validator returns.
3. Negative control: the `>= 3.6.2` build and a benign artifact. Do not exfiltrate or read real data; the proof is execution-order evidence.

### Cognee non-superuser LLM-config overwrite

1. Provision a disposable Cognee (`< 1.5.0`) with one synthetic superuser and one synthetic non-superuser.
2. From the non-superuser session, attempt one benign LLM-config write (e.g. set a marker model id). Record whether the global LLM configuration changes.
3. Negative control: the `>= 1.5.0` build and the same request from a properly scoped role. Do not point the overwritten config at a real LLM provider key, external endpoint, or shared production deployment; the proof is the config write decision, not a live model call.

## Durable operator value

1. **Ingest-then-fetch is the SSRF class.** Any AI pipeline that accepts a URL and fetches it server-side (document partitioning, RAG ingestion, tool fetch) is an SSRF surface. The reusable check is: *is there a server-side allow/deny network gate, and does it apply to the final resolved host, not just the first hop?*
2. **Redirect hops defeat naive SSRF gates.** A check that validates the requested URL but not the post-redirect destination is the `crewai-tools` pattern. Audit every fetch for redirect-follow behavior.
3. **Checkpoints and serialized artifacts are trusted artifacts.** A `.ckpt`/pickle that runs user-supplied callables on load is RCE-by-file. The reusable check is: *does the loader invoke `_instantiator`/`__reduce__` before validation, and can a low-priv actor supply the file?*
4. **AI-platform global config is a privilege surface.** Cognee's non-superuser LLM-config overwrite is the same family as model-loading RCE and vector-store tenant bypass — a config/model/identity write that should be role-gated. When auditing AI platforms, test every global config/model/LLM-key write for role enforcement.
5. **Report the trust break, not the CVE count.** Each of the five is one narrow transition; frame each as input → authority crossing with the exact field, endpoint, and canary evidence.

## October 19 follow-up: crewai-tools `SeleniumScrapingTool` never calls `validate_url` at all — the guard exists in the repo, this tool doesn't import it ([GHSA-5595-9g9c-5cc4](https://github.com/advisories/GHSA-5595-9g9c-5cc4) / CVE-2026-112308, high, through 1.15.28)

The September leg on this page covered `crewai-tools` fetch SSRF where the gate ran on hop 0 but not post-redirect. This new advisory is the complementary failure mode in the *same package*: `SeleniumScrapingTool` **never applies the `validate_url` private-address check** — the helper ships in the repo (other tools call it), this one just doesn't. An attacker influencing agent tool input (prompt injection, untrusted page content, task data) directs **headless Chrome** at loopback, RFC1918, or cloud metadata to disclose internal data and cloud credentials.

Rules:

1. **Per-tool guard parity: enumerate every URL-consuming tool in an agent framework, then grep which ones import the SSRF helper.** Frameworks ship N scraping/fetch/browse tools (requests-based, Playwright-based, Selenium-based); the guard's existence proves nothing about coverage. Fingerprint: `import validate_url` present in some tool modules, absent in others = ready-made bug list. Test each tool's URL param against one owned loopback listener + one owned RFC1918-marker listener; a hit from one tool and a block from its sibling is the report.
2. **Browser-backed fetchers widen the blast radius beyond HTTP clients.** Headless Chrome follows redirects, renders subresources, and sends credentials/cookies a raw client wouldn't — and its results come back into the agent's context (full-readback SSRF). For browser tools specifically also probe `file://` navigation (see the browserless leg on the June 5 Crawl4AI page) — protocol guard parity, per transport, per tool.
3. **Same-product second wave = re-sweep signal.** crewai-tools is now twice SSRF-promoted (Sept redirect-hop leg, Oct missing-guard leg) inside six weeks — keep agent-tool libraries on the standing re-sweep list; each new release is a re-enumeration trigger for the whole tool catalog.

Validation boundary: owned listeners only (loopback + a synthetic "internal" marker host), never cloud metadata endpoints, no third-party internal ranges; proof is the inbound hit + returned marker, nothing more.

Tracked no-publish from the same 18:32Z wave: docTR `load_pretrained_params` torch.load without `weights_only` (rh68/112304, pickle-deser class already on this page's checkpoint legs; pre-2.6 torch band), MongoDB PHP BSON recursion DoS (69c3/112368), sqlparse PHP code-injection single (457h/112307), prototype-pollution set-get single (ffhp/112309), GDevelop cred leak (rq3j/112303), IBM MQ/Concert/Cloud-Pak patch-day packs (authenticated DoS/memory-safety singles), RouterOS `ipt_SAME.ko` integer overflow (99hw/112158, vuldb-style detail-free single — watch for KEV given the RouterOS standing watch on CVE-2026-84411), Tapo C320WS adjacent-network overflow (xj9v/105810), ForgeRock refresh-token-as-access-token (vp4v/7043, token-class-confusion class known), Netskope captive-portal rogue-AP gap (4fcp/12254).

## Safety

- **Owned listeners only** for all SSRF legs; no metadata, no RFC1918 production, no uncontrolled public DNS/redirects.
- **Marker-only deserialization proofs**; no real secret/model/weight access.
- **Synthetic roles and canary config** for Cognee; no live LLM provider or shared-deployment mutation.
- **Disposable instances** throughout; coordinate with the asset owner for any non-lab target.

---

*Source: hourly offensive-security scan, 2026-09-03/04. All 5 advisories tracked in the [source index](../notes/source-index.md).*
