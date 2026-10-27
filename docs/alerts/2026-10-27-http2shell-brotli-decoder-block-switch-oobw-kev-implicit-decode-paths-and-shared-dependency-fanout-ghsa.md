# HTTP2Shell — Brotli decoder block-switch OOB write: implicit decode paths, shared-dependency fan-out, and the KEV head-start (CVE-2026-111497)

Source: hourly offensive-security scan, 2026-10-27. CISA added **CVE-2026-111497** ("Google Brotli Unchecked Return Value Vulnerability", CWE-252 + CWE-787) to KEV on **2026-10-27** (catalog `2026.10.27`, 1760 entries, due **2026-11-10**, forensic-triage **No**, ransomware-use Unknown) — notable because **no in-the-wild exploitation has been confirmed**: CISA moved pre-emptively on a brand-name memory-safety bug in code that sits directly on unauthenticated network input. The root flaw is in the Google Brotli C library **1.0.3 through 1.2.0**, fixed in **1.0.10 / 1.1.1 / 1.2.1** via [commit `0ed4268`](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b) — a commit first written in **February 2026** that no downstream project pulled for eight months because the fix itself was labeled low-severity. CVSS: Google CNA 9.2 (v4.0), GitHub advisory 9.8 (v3.1); Node.js rates its own runtime exposure High. Report credit: OpenAI Codex Security; fix landing: Node.js security release **2026-10-21**.

## Confirmed mechanism

A Brotli stream is split into blocks and the decoder switches between block types via `DecodeBlockTypeAndLength()` in `c/dec/decode.c`. In vulnerable versions that function returned a plain boolean where **false meant either "this stream is malformed" or "I need more input"** — callers could not tell the two apart, and on the streaming fast path the return value was **ignored entirely** (hence the CWE-252 → CWE-787 pair).

Craft an input stream that **declares a single block type and then forces a block switch that cannot succeed**. The vulnerable decoder treats the impossible switch as a transient "need more data" and keeps appending attacker-controlled bytes to an **eight-byte internal buffer, writing past its end** — corrupting adjacent decoder state and process memory. Impact ladder: crash → memory disclosure → RCE.

Fix shape (for fingerprinting): decoder returns a dedicated `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (value **-17**) and stops on both the safe and fast paths. Presence/absence of that error constant in a build's error table is a read-only patch-state tell.

## Exploitation status (what's proven vs claimed)

| Claim | Status | Evidence |
|---|---|---|
| OOB write reachable with crafted stream | **Confirmed** | Node.js advisory, CVE record, Brotli 1.2.1 changelog |
| RCE on official, unmodified Node.js build | **Demonstrated in lab, not every attempt** | Imperva Red Team, Node 24.22.0 Linux **arm64** image, via `fetch()` and Express 5 request bodies; 24.22.1 rejects the same input |
| Public PoC code | Available since Oct 21–22 | Reported to crash stock builds; code execution only on deliberately weakened builds |
| Python package corruption | ASan-confirmed, no exploit attempted | OpenSourceMalware analysis |
| In-the-wild exploitation | **None reported** (KEV is pre-emptive) | KEV entry itself says exploitation none |

Akamai telemetry: **61% of networks run affected Node versions**. Treat a crash as the likely outcome everywhere and the shell as a credible risk wherever a service decodes attacker-influenced Brotli.

## Why the fan-out matters more than the runtime patch

The bug lives in the **shared C library**, which is why the name walked Node2Shell → Python2Shell → HTTP2Shell in four days. Three operator-relevant reachability classes:

1. **Inbound (request bodies you inflate).** Express 5 (`5.0.0–5.3.0`) depends on **body-parser 2.0.0–2.3.0, whose `inflate` option defaults to true** — a single `app.use(express.json())` puts the decoder in front of anonymous traffic. Express 4 (body-parser 1.x) answers 415 for `br` but other middleware in the same app may still decode. Python frameworks that inflate `br` bodies are equivalent.
2. **Outbound (responses you fetch) — the WAF-invisible leg.** Node's built-in `fetch()`/undici decodes `Content-Encoding: br` automatically. In Python, **urllib3 (and therefore `requests`), `httpx[brotli]`, `aiohttp`, and Scrapy advertise `Accept-Encoding: br` and decode whenever a Brotli package is merely installed** — the code never imports it. On Debian 12 / Ubuntu 24.04, libcurl links the **system** libbrotli (1.0.9/1.1.0), so `curl --compressed` and everything enabling libcurl auto-decoding is in scope. **Every URL-fetch feature whose target an outsider chooses is a payload delivery channel: webhook deliveries, link previews, "import from URL," crawlers, image proxies, OAuth/OIDC discovery, and AI agents that browse.** If you hunt SSRF, you already have the target list — this turns each of those sinks from "read primitive" into "memory-corruption write."
3. **Direct decode.** `zlib.brotliDecompress*`, `createBrotliDecompress`, `brotli.decompress`, plus tools parsing Brotli-compressed Parquet, JPEG XL, PDFs, archives, caches, and queue messages.

**Not affected** (useful negative controls): pure reimplementations — Java, JavaScript, and C# ports can't reach it; Rust `brotli-decompressor` errors correctly; Go `andybalholm/brotli` had the same logic error but crash-only (fixed 2026-10-23). Default Apache/Nginx only **encode** responses (encoder path). A bare Node HTTP server does not decode bodies — something must call the decoder.

**Bundled/private copies** where a distro or runtime update does NOT fix you (independent tracker state as of 10-24, verify before reporting): .NET `BrotliStream`/`HttpClient` auto-decompression, PHP `brotli` extension, Ruby `brotli` gem, DuckDB, ClickHouse, Apache Arrow bundled build, libjxl, MuPDF, EDK II/UEFITool, YDB, 7-Zip-zstd/p7zip, NanaZip. Fixed already: Chromium, Firefox, ngx_brotli, Brotli4j, Ghostscript. **Bun 1.4.3 and earlier vulnerable, fixed 1.4.4.** Node EOL lines ≤20.x bundle the vulnerable decoder with **no upstream fix ever** (HeroDevs read `decode.c` at each final tag; `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` absent 10.x–25.x).

## Validation boundaries (authorized targets / lab only)

1. **Reachability before anything else, read-only:** `node -p "process.versions.brotli"` pins the decoder bundled in *that exact binary* — the Node version string is not the signal when distro packages link system libbrotli (Debian's tracker listed both nodejs and brotli unfixed across releases on 10-23, with nodejs marked "unimportant" urgency against Node's own High). Check the distro tracker, not just the runtime version.
2. **Code-path grep on owned/labeled targets:** `grep -rnE "express\.json|bodyParser|createBrotliDecompress|brotliDecompress" src/`, `npm ls express body-parser`, and enumerate every outbound-URL feature (the SSRF inventory doubles as the delivery-channel inventory).
3. **In lab only**, replay a malformed single-block-type + forced-block-switch stream (public PoC corpus exists — isolate before running; several "HTTP2Shell scanner" repos are themselves untrusted) against your own Express 5 / fetch sink and record the decision: `400` with a format error = patched decoder rejecting; crash/hang = vulnerable. **Do not send exploit traffic at third-party production** — on vulnerable builds a crash is the expected outcome, i.e., you are DoSing, and the RCE path is not in scope without explicit authorization.
4. **Negative control** on the fixed build (Node 24.22.1+ rejects the identical input with a format error; the `-17` constant is present).

## Durable operator value

1. **Implicit codec negotiation is attack surface activated by dependency install, not by code.** `pip install brotli` flips `Accept-Encoding: br` on for every urllib3 consumer in the environment. When fingerprinting a target's stack, the question is which codecs are *enabled by what is installed*, matching the DRF `charset=` attacker-named-codec axis: transform parameters at the parser boundary are a fuzz set of their own.
2. **Version-matching a shared C dependency through the runtime string lies.** Three genealogies to check separately: runtime-bundled copy (`process.versions.brotli`), distro system library (tracker, `ldd`), and vendored private copies (.NET, Arrow, DuckDB...). Exposure validation, not version inventory, is the deliverable.
3. **Outbound-decode memory corruption turns SSRF sinks into write primitives without touching inbound rules.** No WAF sees the response leg. For any SSRF found in a Node/Python stack, the report escalation path now includes: serve a crafted `Content-Encoding: br` response from your owned redirector *only in authorized lab validation*, and report the reachability, not the exploit.
4. **CWE-252-on-a-decoder is a grep class:** any streaming parser whose status return conflates "malformed" with "incomplete," especially where a fast path ignores the return value. Same producer/consumer-drift family as the Oct 23 PHP2Shell bailout lifecycle — fuzz malformed framing, watch for writes past small fixed buffers.
5. **A KEV entry without confirmed ITW = CISA pre-empting; the scanner swarm starts now, not at first incident.** Same timing-gap logic as the Oct 23 Collabora nine-day lag: assume commodity probing of `Content-Encoding: br` paths across the estate within days. 61% estate prevalence says this is the largest-footprint decode path currently exposed.
6. **The eight-month un-pulled fix is a supply-chain tell for your own hunting:** severity labels on upstream commits suppress backports. When hunting vendor patch gaps, diff security-relevant upstream commits that were never tagged as security — that's where "patched upstream, vulnerable downstream" fleets live.

## Safety

Authorized scope only; lab reproduction on owned builds only; do not run untrusted scanner/PoC code outside isolation; no production exploit traffic; redact any memory-disclosure output — it is someone's process memory.

---

*Sources: [CISA KEV catalog 2026.10.27](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-111497) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-111497) · [Brotli fix commit 0ed4268](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b) · [Sysdig: Node2Shell detection](https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce) · [Akamai: Inside Node2Shell](https://www.akamai.com/blog/security-research/inside-node2shell-closer-look-cve-2026-111497) · [Strobes: HTTP2Shell blast radius](https://strobes.co/blog/http2shell-brotli-rce-cve-2026-111497/) · [HeroDevs: EOL-line verification](https://www.herodevs.com/blog-posts/cve-2026-111497-node2shell-node-js-brotli-rce) · [Aikido: HTTP2Shell](https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497)*
