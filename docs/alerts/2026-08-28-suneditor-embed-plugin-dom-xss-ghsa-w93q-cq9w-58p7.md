# SunEditor Embed plugin DOM XSS via script-element recreation, operator validation

**Date reviewed:** 2026-08-28
**Advisory:** [GHSA-w93q-cq9w-58p7 / CVE-2026-54606](https://github.com/advisories/GHSA-w93q-cq9w-58p7)
**Severity:** High
**Affected:** `suneditor` <= 3.1.3 (patched 3.1.4)
**Boundary class:** rich-text editor sanitize step that parses attacker-controlled embed HTML, then *re-creates and appends* `<script>` elements from parsed nodes, a DOM XSS via parser round-trip

## What is durable here

Most editor-XSS findings are "the sanitizer let a tag through." This one is a different, more reproducible primitive: **the sanitizer does see the `<script>` element, but the plugin's own node-recreation path re-injects it into the live DOM**, where a freshly created and appended script element executes by spec.

The relevant behavior in the Embed plugin:

```js
const embedDOM = new DOMParser().parseFromString(src, 'text/html').body.children;
if (/^script$/i.test(chd.nodeName)) {
  scriptTag = dom.utils.createElement('script', {
    src: chd.getAttribute('src'),
    async: 'true'
  }, null);
  continue;
}
cover.appendChild(scriptTag);
```

Two properties make this a clean bug-hunting pattern:

1. **The trigger is a crafted *sequence***: a valid `<iframe>` embed first, then an external `<script src=...>` element. The iframe primes the embed-processing path; the script element is what executes.
2. **The sink is DOM re-creation, not string injection**: the payload is data the DOM parser already accepted. No HTML entity escaping issue, no CSP bypass needed (it is a same-page, same-origin execution context for any `src` the browser will load).

The durable operator question for any rich-text editor with an embed/iframe feature: **does the embed processor treat `<script>` child nodes as inert data, or does it clone/recreate them into the live document?** A DOMParser round-trip plus `appendChild` of a recreated `<script>` is always executable, regardless of what the string-level sanitizer decided.

## Recon

1. Confirm the app embeds SunEditor (or a similar rich-text editor with an embed/iframe plugin) with version <= 3.1.3. Look for the `suneditor` asset path, the `Embed` plugin registration, or the embed-modal markup.
2. Determine who can write embed content:
   - **Stored:** any user who can save editor content (comments, articles, tickets, CMS pages). Highest value: content that is later opened in the editor context by a *higher-privilege* user (editor/admin preview or edit).
   - **Reflected:** a preview endpoint or draft-save flow that round-trips the payload without persisting it.
3. Check whether the app applies a *second* server-side sanitizer on read. The advisory's impact statement hinges on content being stored or reflected "without additional backend sanitization", if the backend strips `<script>` on save, the chain is blocked at the storage layer and the finding is lower impact.

## Validation workflow (authorized lab / customer-approved)

All proofs use a lab origin and an inert local payload server. Do not load scripts from third-party origins, do not target real admin users, and do not persist payloads into production content stores.

1. Stand up a lab origin that hosts a SunEditor instance with the Embed plugin enabled (<= 3.1.3 for the vulnerable control, 3.1.4 for the patched control).
2. Host an inert beacon:

   ```bash
   mkdir -p /tmp/suneditor-poc && cd /tmp/suneditor-poc
   cat > poc.js <<'EOF'
   console.log("SKILLZ_EMBED_XSS_CANARY_EXECUTED");
   EOF
   python3 -m http.server 8000
   ```

   The beacon logs a marker and prints it; no exfiltration, no cookie access, no DOM traversal.
3. Through the Embed modal, insert the canary payload:

   ```html
   <iframe src="https://example.invalid/embed-canary"></iframe><script src="http://127.0.0.1:8000/poc.js"></script>
   ```
4. Save, then open the stored/previewed content in a fresh browser context (or re-enter the editor).
5. Capture:
   - **Positive control (vulnerable):** the lab payload server logs `GET /poc.js` and the page console shows the canary string, proof the recreated script executed in the victim context.
   - **Patched control (3.1.4):** no fetch of `poc.js`, no console canary; the embed is rendered without executing the appended script.
   - **Negative control:** an embed with only the `<iframe>` and no `<script>`, confirms the beacon server is reachable and the trigger is the script element, not network conditions.

## Evidence to capture

- Exact embed HTML submitted and the stored representation (server-side sanitizer decision visible here).
- Raw network log of the beacon request (path only; no real cookies/tokens in the capture).
- Console output of the inert canary in the victim-context tab.
- Version matrix: `suneditor` version, patch state, execution observed (yes/no).

## Reporting heuristic

Frame the finding as **editor sanitize round-trip -> script element re-creation -> live-DOM execution**, not as a generic stored XSS:

- Name the editor, plugin, and exact node-recreation path.
- Show the two-layer structure: string-level sanitization saw the tag, DOM-level re-injection executed it.
- State the stored vs reflected distinction and whether a backend second sanitizer exists.
- Keep the PoC to the inert beacon; do not publish a cookie-stealing payload.

## Safety constraints

- No script execution against production admin/editor accounts.
- Beacon server on loopback or a lab origin only; no third-party CDN or public pastebin.
- No persistence of the payload into a shared or production content store.
- No `alert()` chains that would disrupt a real user session; use a silent console marker in any semi-interactive validation.

## Sources

- GitHub Security Advisory: [GHSA-w93q-cq9w-58p7 / CVE-2026-54606](https://github.com/advisories/GHSA-w93q-cq9w-58p7)
- Upstream issue: https://github.com/JiHong88/suneditor/issues/1649
- Fix commit: https://github.com/JiHong88/suneditor/commit/9d43a5e082101d2d6475cba86e0d58d7c2cf6677
