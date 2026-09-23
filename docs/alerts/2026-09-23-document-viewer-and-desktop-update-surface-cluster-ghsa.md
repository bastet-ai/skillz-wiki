---
title: "Document viewer and desktop update surfaces — Foxit pack, Tauri manifest downgrade, localhost listener inventory (Sept 23 09:30Z wave)"
---

# Document viewer and desktop update surfaces (Sept 23 09:30Z wave)

A September 23 09:30Z GitHub advisory wave landed a **~40-GHSA Foxit PDF Editor/Reader pack**, the **Tauri updater plugin's unsigned-manifest downgrade** (companion to the `allowDowngrades` XSS bridge folded Sept 22), and an **Acer NitroSense localhost-listener pair**. Individually most items are "memory-safety in a desktop app"; together they form a durable operator playbook for the two surfaces every engagement touches and almost nobody audits systematically: **document viewers** (the #1 phishing delivery target) and **desktop updaters / localhost IPC** (the #1 silent-lateral path on endpoints).

## 1. Signature coverage vs displayed content — incremental-update signature survival (Foxit, CVE-2026-91814 / [GHSA-c9r7-69j9-jq5j](https://github.com/advisories/GHSA-c9r7-69j9-jq5j), medium)

Foxit's handling of **incrementally updated** PDF documents lets changes to visible content pass while the existing signature still renders as valid. This is the PDF spelling of the invariant already canonical on the [May 26 signature-boundary page](2026-05-26-template-container-cms-ics-and-signature-boundary-batch-ghsa.md) for Fedify JSON-LD shape confusion: **the signature verifies a copy of the document, and the viewer displays a different copy.**

- PDF incremental updates append a new xref/body segment to the original bytes; a signature's byte ranges were fixed at signing time. Content added or re-pointed in the appended segment is *outside what was signed* but *inside what is displayed*.
- Sweep rule for any signed-document validator (PDF, XML-DSG, JOSE-detached, S/MIME with mutable wrappers): take one legitimately signed document, then (a) append an incremental-update segment with a new/changed visible page, (b) re-point an object via the appended xref, and (c) check whether the validator's verdict, the badge in the UI, and the rendered text agree. A valid-badge-over-altered-render is the finding; "signature still validates" is *not* the negative control — the UI verdict is.
- Report framing for bounty/consulting work: signed-contract/signed-invoice workflows are the impact story (content spoofing that survives the signature badge), not parser quality.
- Lab-only: sign your own PDF with a self-signed cert; never present forged signature tests against real signed agreements you don't own.

## 2. Viewer permission flags are enforced only where code checks them — SMB hash leak with no prompt (Foxit, CVE-2026-91796 / [GHSA-3q39-rxpg-hqqg](https://github.com/advisories/GHSA-3q39-rxpg-hqqg), medium)

Foxit's interface **lacks the permission verification required for secure reading mode**, so a crafted PDF can trigger **external SMB authentication with no security prompt**, leaking the user's **credential hash** (classic `\\attacker\share` NTLM capture) just from opening the file.

- Operator axis: **document "protected view"/secure-mode restrictions are a policy object the viewer must consult at every outbound primitive** (external links, embedded URLs, remote template loads, *SMB/UNC references*). Any reader feature that opens a network resource is an NTLM-coercion primitive; the prompt/permission layer is a separate gate that gets forgotten per-feature.
- Initial-access red team pattern: crafted-PDF SMB coercion is the same play as the printer/PDF coercion families — pair with Responder/NTLM-relay posture on the outbound path you can legitimately see; capture hashes against **your own** responder only, and hash → crack/relay decisions stay inside engagement scope.
- Hunt rule for any document viewer/editor you're authorized to fuzz: grep/reference-test for every URL/UNC/file-path resolution reachable from document content (annotations, embedded files, XObjects, form actions) and check which ones fire **without the user-permission prompt** in hardened mode. The missing prompt is the finding.

## 3. Same-process document isolation — cross-document reads via the JS interface (Foxit, CVE-2026-91788 / [GHSA-mw87-v3r3-7j2h](https://github.com/advisories/GHSA-mw87-v3r3-7j2h), medium)

Foxit's JavaScript interface **omits the attribute-authorization checks required by the PDF specification**, so a trusted malicious PDF can read sensitive content from **other documents open in the same process** and transmit it out.

- Durable axis: desktop apps routinely assume *per-document* isolation while running all documents in **one process** with one script engine. Enumerate the script API surface (PDF-LA JS, Office VBA/OMAuto, editor extension APIs) for attributes/objects that resolve "current/other document" globally rather than per-sandbox; a document-scoped security model over a process-scoped object graph is the bug shape.
- This is the desktop twin of the browser same-origin-object oracles (Sept 22 GHES name-scoped token page): *authorization scoped to A, object graph scoped to the containing process/session.*
- Validation stays in a lab with two synthetic documents you own; prove with a marker string from document B surfacing in document A's script context plus an owned listener; never test on documents containing real third-party content.

## 4. The updater is a privileged file consumer — MITM, swap window, and LPE (Foxit 91812/91813/91803/91800/91798 pack)

| Advisory | Behavior |
| --- | --- |
| [CVE-2026-91812 / GHSA-748f-jhmv-j7jm](https://github.com/advisories/GHSA-748f-jhmv-j7jm) | Update mechanism lets **MITM attackers bypass certificate validation and package integrity checks** → code execution with system privileges. |
| [CVE-2026-91813 / GHSA-597r-vgr7-9622](https://github.com/advisories/GHSA-597r-vgr7-9622) | Update package **swapped between download and high-privilege extraction** (insufficient file locking + integrity revalidation) → local privileged code execution. |
| CVE-2026-91803 / 91800 / 91798 | Local privilege escalation in the **updater, macOS installer, and update daemon** (insecure permissions/paths class). |

Reusable updater audit — this pair completes the Foxit-style updater checklist for *any* desktop/daemon updater:

1. **Transport:** is the update fetch pinned (cert pinning or pubkey-pinned metadata)? A "TLS" download with validator-bypassable cert checks is a plaintext download for anyone on-path. Test only on lab networks you control with a lab MITM proxy.
2. **Metadata authenticity:** is the *descriptor* (version, URL, hash) signed, or only the payload? See §5 — unsigned descriptors convert a signed-payload guarantee into a downgrade channel.
3. **Swap window:** is the downloaded file re-verified *at extraction time* by the privileged process, or verified earlier by the unprivileged one? Download-dir writability + delayed privileged extraction = TOCTOU LPE — the same extract-before-verify family as Grafana plugins (Sept 18) and the tar-file filter verdict drops (May 6). Check dir ACLs as the low-priv user and the extraction account separately.
4. **Privileged helper hygiene:** updater/daemon/installer service — what paths does it write, load DLLs from, or chmod with elevated rights? (World-writable install dirs and unquoted service paths are the classic spells; the advisory pack says all three helper binaries carry class bugs.)

## 5. Tauri updater: signature covers the binary, manifest is the attack (CVE-2026-95625 / [GHSA-p8c6-29q6-cqw7](https://github.com/advisories/GHSA-p8c6-29q6-cqw7), medium)

The Tauri updater plugin verifies update **binaries** with minisign signatures, but the **manifest** — version number, download URL, signature field — is fetched over TLS and **never itself signed**. The only anti-rollback check compares the manifest's **unsigned** `version` field against the current version, so an attacker who can serve a crafted manifest **forces installation of any older signed release without the developer's private key**.

- The invariant: **authenticate the descriptor, not just the payload.** "The binary is signed" tells you nothing until you ask *which copy of the update data decides which binary gets installed* — here that copy (the manifest) is unauthenticated. Same-shape families already on the wiki: patch-the-payload-vs-check-the-metadata (Sept 18 Grafana extract-before-verify), and `if (state==X) verify()` skip conditions (Sept 23 payment cluster).
- Downgrade ≠ theoretical: the Sept 22 `allowDowngrades`-from-webview bug ([CVE-2026-95624](2026-08-05-workspace-fetch-object-interpreter-boundaries-ghsa.md#september-22-evening-followup-tauri-updater-anti-rollback-is-frontend-controllable--sandbox-secrets-in-world-readable-argv)) made anti-rollback XSS-disableable from JS; this second advisory makes it **network-disableable for anyone in the manifest path** (DNS/TLS-terminating middleboxes, compromised-but-not-forged hosting). Two advisories, one component, opposite entry points — when you find one broken gate on an updater, enumerate every field that gates version selection, transport, and acceptance separately.
- Audit rule for any update framework (Tauri, Squirrel, Sparkle, Electron-updater, OTA stacks): diff *what the signature covers* vs *what the install-decision code reads*. Prove in a lab app with your own keypair: serve a valid old release's signed binary under a manifest claiming it's the "update"; acceptance without a fresh-version signature is the finding. Never test against a vendor's live update endpoint.

## 6. Desktop app localhost inventory — production DevTools and unauthenticated IPC to `execSync` (Acer NitroSense, CVE-2026-50228/50227 / [GHSA-xv7c-3mjr-8rg4](https://github.com/advisories/GHSA-xv7c-3mjr-8rg4), [GHSA-x445-jgfc-928v](https://github.com/advisories/GHSA-x445-jgfc-928v))

Acer NitroSense (preloaded on Acer gaming laptops):

- **Chromium remote debugging left enabled in the production build**: unauthenticated local attacker connects to the **Electron DevTools endpoint on localhost TCP 9993** → execute JavaScript in the privileged application context → arbitrary code execution.
- **MQTT broker exposed over a localhost WebSocket endpoint with no auth** → invoke the app's `ddsc` RPC functions **including `child_process.execSync()`** → arbitrary command execution in the app context.

Durable axes:

- **Post-access local recon:** on any Windows/Linux endpoint, enumerate localhost listeners before hunting credentials — OEM/preloaded suites (Acer, ASUS, MSI, Lenovo, Killer/Bigfoot networking stacks) ship always-on localhost RPC services with zero authentication because "localhost = trusted". Quick pass: `netstat -ano`/`Get-NetTCPConnection -State Listen` + `Get-Process -Id` per port, fingerprint the owning binary's version info, fuzz anything that smells like JSON-RPC/MQTT/DevTools (`GET /json/version` on an unknown port answering JSON = Electron DevTools).
- **DevTools-in-production is a class, not an accident:** a `--remote-debugging-port` build shipped at scale converts *any* local user into app-context code execution — and browser-driven exploitation (drive-by from web content to localhost) is the escalation leg below.
- **Web-content → local native service bridges:** same wave, **CGServiSign** ([CVE-2026-15027 / GHSA-q25p-jh2x-hv2j](https://github.com/advisories/GHSA-q25p-jh2x-hv2j), high, sparse detail) is OS command injection in a **local service interface reachable by inducing a victim to visit a malicious web page** — the browser-side variant of the same localhost-trust gap (native service listens on loopback, accepts requests steerable from web content, and reaches a shell). Chinese e-gov/banking sign-controls (Changing/EGoon style) are a large install base worth scanning in targeted-scope internal engagements.
- Validation: prove with an inert RPC call whose effect you patch/observe (or a JS marker evaluated in your own session on your own machine); never run destructive commands through a discovered `execSync` sink, and report port + version + auth-state as the evidence.

## Same-wave Foxit memory-safety items — tracked, not published

The remaining ~30 Foxit GHSAs (CVE-2026-91789–91818: UAFs in annotations/JS/page-tree/form handling, heap OOB read/write in WebP/JPEG2000/rendering paths, embedded-resource and attachment **path traversal** writes 91801/91797, FileOpen encryption-metadata pointer misuse 91795, reentrant-zoom recursion 91791/91792) are the parser memory-safety class already canonical on this wiki (per pypdf/ImageMagick precedent): relevant if you build authorized client-side fuzzing/phishing-simulation campaigns, but no new replayable operator axis beyond §1–§3. Note the two **file-write path traversals** (91801 embedded resources, 91797 attachment filenames) as the highest-value subset for a delivery-chain engagement — viewer writes outside the intended directory combine with the updater/autoloader locations from §4.

## Tracked without publication (rest of the 09:30Z wave)

- **Apache Doris FE meta-service improper authentication** (CVE-2026-31377 / [GHSA-6cx7-4x8x-cqpx](https://github.com/advisories/GHSA-6cx7-4x8x-cqpx), high, fixed 4.0.8/4.1.4) — **client-supplied node information used as authentication** on internal FE metadata endpoints; folded on the [Sept 21 auth-precedence page](2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md).
- **Rename wp-login.php SQLi via `log`** (CVE-2026-93368) + Advanced Contact form 7 DB contributor shortcode read-all (6831) + Getwid `eval()` stored XSS (5924) — folded on the [Sept 19 WP alternate-surface page](2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md).
- Apache BuildStream `tar` source-plugin symlink write on Python <3.12 (CVE-2026-82331) — sibling of the May 6 extraction-page family (same symlink-escape shape; mitigation is the tarfile data-filter that already appears there); tracked, no new axis.
- NT-ware uniFLOW Online logout-session retention under Service Offline Emergency Mode timing window (CVE-2026-92378) — print-management appliance session-lifecycle edge, sparse; tracked.
- ASR Crane/Falcon kernel NULL-deref (CVE-2026-42801) and the wave's remaining memory-safety singles — kernel/driver class, tracked per precedent.

## Evidence and reporting boundaries

- Document-signature proofs use self-signed lab documents only; the finding is badge-vs-render divergence, not "I broke the signature."
- SMB-coercion proofs run against your own responder on lab networks you control; hashes captured are yours to discard and never leave the engagement boundary.
- Updater/downgrade proofs run in a lab app with your own keypair and your own update server; never MITM, spoof, or replay against a vendor's live update infrastructure.
- Localhost-service findings stop at reachability + one inert patched/instrumented call; discovered `execSync`-style sinks are documented, not exercised destructively.
- Cross-document isolation proofs use two synthetic documents you own; never read real third-party content as the marker.
